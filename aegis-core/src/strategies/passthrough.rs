use super::Strategy;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct PassthroughStrategy;

#[async_trait]
impl Strategy for PassthroughStrategy {
    fn id(&self) -> &'static str {
        "passthrough"
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
