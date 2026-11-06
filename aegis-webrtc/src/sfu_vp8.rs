//! Bounded native VP8 media adapter for the broker-owned SFU pixel grid.
//!
//! This module requires the explicit `sfu-media-vp8` feature and libvpx.
//! It does not admit a public SFU route or change `UnsupportedSfu`.

use crate::sfu_media::{MediaError, PixelGrid};
use std::num::NonZero;
use vpx_rs::{
    dec::CodecId as DecoderCodec, enc::CodecId as EncoderCodec, DecodedImageData, Decoder,
    DecoderConfig, Encoder, EncoderConfig, EncoderFrameFlags, EncodingDeadline, ImageFormat,
    Packet, RateControl, Timebase, YUVImageData,
};

const SIDE: usize = 256;
const RGB_BYTES: usize = SIDE * SIDE * 3;
const YUV_BYTES: usize = SIDE * SIDE * 3 / 2;
const MAX_FRAME: usize = 1024 * 1024;

/// A fresh instance is owned by exactly one role and one LiveKit track.
/// The caller must retain this instance for the full session; decoder state
/// must not be reset to accept a retransmission as a new authenticated frame.
pub struct Vp8GridCodec {
    encoder: Encoder<u8>,
    decoder: Decoder,
    next_pts: i64,
}

impl Vp8GridCodec {
    pub fn new() -> Result<Self, MediaError> {
        let mut enc = EncoderConfig::<u8>::new(
            EncoderCodec::VP8,
            SIDE as u32,
            SIDE as u32,
            Timebase {
                num: NonZero::new(1).ok_or(MediaError::Frame)?,
                den: NonZero::new(10).ok_or(MediaError::Frame)?,
            },
            RateControl::ConstantBitRate(512),
        )
        .map_err(|_| MediaError::Frame)?;
        enc.threads = 1;
        enc.lag_in_frames = 0;
        let mut dec = DecoderConfig::new(DecoderCodec::VP8, SIDE as u32, SIDE as u32);
        dec.threads = 1;
        Ok(Self {
            encoder: Encoder::new(enc).map_err(|_| MediaError::Frame)?,
            decoder: Decoder::new(dec).map_err(|_| MediaError::Frame)?,
            next_pts: 0,
        })
    }

    /// Encode one already sealed 64-byte frame as one VP8 video sample.
    /// Refuse buffered/multiple output so a caller cannot silently misbind
    /// RTP timestamps to AEAD sequence numbers.
    pub fn encode_wire(&mut self, wire: &[u8; 64]) -> Result<Vec<u8>, MediaError> {
        let pixels = PixelGrid::encode(wire);
        let yuv = grayscale_i420(&pixels)?;
        let image = YUVImageData::from_raw_data(ImageFormat::I420, SIDE, SIDE, &yuv)
            .map_err(|_| MediaError::Frame)?;
        let packets = self
            .encoder
            .encode(
                self.next_pts,
                1,
                image,
                EncodingDeadline::default(),
                // A lost media frame must not make a later AEAD sequence
                // undecodable through VP8 inter-frame prediction.
                EncoderFrameFlags::FORCE_KF,
            )
            .map_err(|_| MediaError::Frame)?;
        self.next_pts = self.next_pts.checked_add(1).ok_or(MediaError::Sequence)?;
        let mut out = None;
        for packet in packets {
            if let Packet::CompressedFrame(frame) = packet {
                if out.is_some() || frame.data.is_empty() || frame.data.len() > MAX_FRAME {
                    return Err(MediaError::Frame);
                }
                out = Some(frame.data.to_vec());
            }
        }
        out.ok_or(MediaError::Frame)
    }

    /// Decode exactly one 256x256 VP8 frame and recover the authenticated
    /// pixel grid from its luma plane. The AEAD/replay codec still decides
    /// whether the recovered wire is admissible.
    pub fn decode_wire(&mut self, encoded: &[u8]) -> Result<[u8; 64], MediaError> {
        if encoded.is_empty() || encoded.len() > MAX_FRAME {
            return Err(MediaError::Frame);
        }
        let frames = self
            .decoder
            .decode(encoded)
            .map_err(|_| MediaError::Frame)?;
        let mut pixels = None;
        for frame in frames {
            if pixels.is_some() || frame.width() != SIDE as u32 || frame.height() != SIDE as u32 {
                return Err(MediaError::Frame);
            }
            let DecodedImageData::Data8b(data) = frame.data() else {
                return Err(MediaError::Frame);
            };
            if data.format() != ImageFormat::I420 {
                return Err(MediaError::Frame);
            }
            let planes = data.planes();
            let stride = planes.y_stride();
            if stride < SIDE || planes.y.len() < stride * SIDE {
                return Err(MediaError::Frame);
            }
            let mut rgb = vec![0u8; RGB_BYTES];
            for row in 0..SIDE {
                for col in 0..SIDE {
                    let value = planes.y[row * stride + col];
                    rgb[(row * SIDE + col) * 3..(row * SIDE + col) * 3 + 3].fill(value);
                }
            }
            pixels = Some(rgb);
        }
        PixelGrid::decode(&pixels.ok_or(MediaError::Frame)?)
    }
}

fn grayscale_i420(rgb: &[u8]) -> Result<Vec<u8>, MediaError> {
    if rgb.len() != RGB_BYTES || rgb.chunks_exact(3).any(|p| p[0] != p[1] || p[1] != p[2]) {
        return Err(MediaError::Frame);
    }
    let mut yuv = vec![128u8; YUV_BYTES];
    for (dst, pixel) in yuv[..SIDE * SIDE].iter_mut().zip(rgb.chunks_exact(3)) {
        *dst = pixel[0];
    }
    Ok(yuv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grayscale_contract_refuses_colour_or_size_drift() {
        let mut rgb = vec![127u8; RGB_BYTES];
        let yuv = grayscale_i420(&rgb).unwrap();
        assert_eq!(yuv.len(), YUV_BYTES);
        assert!(yuv[SIDE * SIDE..].iter().all(|&sample| sample == 128));
        rgb[2] = 126;
        assert!(grayscale_i420(&rgb).is_err());
        assert!(grayscale_i420(&rgb[..RGB_BYTES - 3]).is_err());
    }

    #[test]
    fn real_vp8_roundtrip_and_wrong_frame_refusal() {
        let mut codec = Vp8GridCodec::new().unwrap();
        let wire = [0x55u8; 64];
        let encoded = codec.encode_wire(&wire).unwrap();
        assert_eq!(codec.decode_wire(&encoded).unwrap(), wire);
        assert!(codec.decode_wire(&vec![0; MAX_FRAME + 1]).is_err());
    }
}
