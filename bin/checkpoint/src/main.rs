use anyhow::{Result, anyhow};
use sui_rpc::proto::sui::rpc::v2::{
    SubscribeCheckpointsRequest, subscription_service_client::SubscriptionServiceClient,
};

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = tonic::transport::Channel::from_static("https://fullnode.mainnet.sui.io:443")
        .tls_config(tonic::transport::ClientTlsConfig::new().with_enabled_roots())
        .map_err(|e| anyhow!("Failed to configure TLS: {}", e))?;

    // 配置連接參數並使用 lazy 連接
    let channel = endpoint
        // 连接阶段超时：短一些，失败就重试
        .connect_timeout(std::time::Duration::from_secs(5))
        // 请求阶段超时：给服务器足够时间处理重载下的大请求
        .timeout(std::time::Duration::from_secs(30))
        // HTTP/2 ping，避免空闲时被中间设备回收
        .http2_keep_alive_interval(std::time::Duration::from_secs(10))
        .keep_alive_while_idle(true)
        // TCP keepalive（内核层）
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .connect_lazy();

    let mut subscription_service_client = SubscriptionServiceClient::new(channel);

    let mut request = SubscribeCheckpointsRequest::default();
    request.read_mask = Some(sui_rpc::field::FieldMask {
        paths: vec![
            "sequence_number".to_string(),
            "summary".to_string(),
            // "transactions.events".to_string(),
        ],
    });

    let mut response = subscription_service_client
        .subscribe_checkpoints(request)
        .await?
        .into_inner();

    while let Some(message) = response.message().await? {
        if let Some(checkpoint) = message.checkpoint {
            println!("Received checkpoint: {:?}", checkpoint.sequence_number());
            let summary = checkpoint.summary();

            // 打印时间差
            if let Some(ts) = summary.timestamp {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let checkpoint_time = (ts.seconds as u64 * 1000) + (ts.nanos as u64 / 1_000_000);
                let time_diff = now.saturating_sub(checkpoint_time);

                println!("⏰ Checkpoint delay: {}ms", time_diff);
            }
        }
    }

    Ok(())
}
