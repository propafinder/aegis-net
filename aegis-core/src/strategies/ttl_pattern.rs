//! Установка IP TTL для исходящих сегментов (Linux/macOS через socket2). Эвристика «TTL manipulation».

use super::Strategy;
use async_trait::async_trait;
use socket2::SockRef;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct TtlPatternStrategy {
    pub ttl: u32,
}

impl Default for TtlPatternStrategy {
    fn default() -> Self {
        Self { ttl: 60 }
    }
}

#[async_trait]
impl Strategy for TtlPatternStrategy {
    fn id(&self) -> &'static str {
        "ttl_pattern"
    }

    async fn send_first(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        _sni: Option<(usize, usize)>,
        _ctx: &super::SendFirstContext,
    ) -> std::io::Result<()> {
        // `SockRef::from(&mut TcpStream)` конфликтует с версией socket2 у tokio — используем shared ref.
        let sock = SockRef::from(&*stream);
        // socket2 0.6: отдельные TTL для v4/v6; для исходящего TCP обычно достаточно v4.
        let _ = sock.set_ttl_v4(self.ttl);
        stream.write_all(data).await
    }
}
