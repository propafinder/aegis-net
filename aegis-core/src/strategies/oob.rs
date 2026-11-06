//! Compatibility first-buffer sender for the historical `oob_data` identifier.
//!
//! Canonical application bytes remain in the ordinary TCP stream. Sending one
//! of them as urgent data can remove it from an ordinary receiver; a raw write
//! also cannot claim successful completion after a partial count. This alias
//! does not perform urgent-data manipulation or establish DPI evasion.

use super::Strategy;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct OobDataStrategy;

#[async_trait]
impl Strategy for OobDataStrategy {
    fn id(&self) -> &'static str {
        "oob_data"
    }

    async fn send_first(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        _sni: Option<(usize, usize)>,
        _ctx: &super::SendFirstContext,
    ) -> std::io::Result<()> {
        stream.write_all(data).await
    }
}

#[cfg(test)]
#[path = "oob_tests.rs"]
mod tests;
