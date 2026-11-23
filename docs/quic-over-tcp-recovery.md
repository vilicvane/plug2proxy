# QUIC over TCP：基于内核 TCP_INFO 的三态健康与无损恢复

仅 Linux 的 QomT 主连接启用此模式。UDP 旁路保留标准 QUIC 丢包检测、PTO 和 pacing；未提供 `TCP_INFO` 采样的平台仍使用标准 QUIC 恢复。

## 三态路径模型（Clean / Stalling / Dead）

每条 TCP 每 50 ms 读取内核 `TCP_INFO`（`tcpi_ca_state`、`tcpi_backoff`、`tcpi_probes`、`tcpi_unacked`、`tcpi_notsent_bytes`、`tcpi_bytes_acked`、`tcpi_delivered` 等），把**调度选路**与**路径生死**严格拆开：

1. **顺畅（Clean）**：
   - 发送缓冲区为空（`unacked == 0 && notsent_bytes == 0`，闲置连接天然保持 Clean，无需周期发送零长度探测帧），或未进入 `Loss`、无未响应超时退避且累计确认未超出队头停滞窗口 `max(500ms, 2 × RTO, 4 × (RTT + RTTvar))`。
   - 正常派发新 QUIC 包。
2. **补洞 / 拥塞（Stalling）**：
   - 存在未确认或未发完数据，且出现队头停滞（超出 `stall_window`）、进入 `TCP_CA_Loss` 或出现退避（`backoff / probes >= 1`），但尚未满足 Dead 条件（例如对端仍在通过 SACK 推进 `tcpi_delivered`，或连续未响应 RTO 次数 `< 3`）。
   - **仅暂停向该连接派发新包**，避免新包排在队头洞后被阻塞；**绝不调用 `ReliableTransport::fail()`**，待内核补完洞后沿用同一发送代次恢复，不产生假丢包与重复重传。
3. **真死路（Dead）**：
   - 连接读写关闭 / 报错，或在有待确认数据时 `tcpi_delivered` 与 `tcpi_bytes_acked` 均无任何推进（纯反向收包、无新 SACK 的旧重复 ACK 均不会推进 `tcpi_delivered`），持续超过 `max(3s, 8 × (RTT + RTTvar))` 且连续未响应超时 `max(backoff, probes) >= 3`。
   - 立即标记该代次 `fail()`，通知 QUIC 将该连接上未确认的帧迁移到健康连接重发；若池中存在其他存活连接则直接关闭该半死 socket 触发重连替换（若仅剩最后一条连接则待新连接建立或 `TCP_USER_TIMEOUT` 到期时清理）。

## 跨路迁移不触发外层拥塞窗口塌缩

在 `reliable_transport` 模式下，底层每条 TCP 连接已由各自内核 TCP BBR 独立控速；单条死路触发 `ReliableTransport::fail()` 属于跨 TCP 路径故障转移而非网络拥塞丢包，`quiche` 仅回收在途字节并重排帧，用 `on_packet_neutered` 清理采样状态，**不触发外层全局 `cwnd` 削减**。

## 跨 TCP 乱序

TCP 模式使用 4 字节 QUIC 包号，并按实际 TCP 连接维护独立、固定大小的接收包号记录。不同 TCP 之间迟到超过原 8192 包窗口的包仍可处理；同一 TCP 必须按线上顺序交给 quiche。

待发送的 ACK 范围分批编码，每批最多 68 个范围，避免迟到包的 ACK 被容量淘汰。已发出的范围由该 ACK 包的发送记录持有；承载它的 TCP 失效时重新加入待确认范围。QUIC ACK 本身丢失也能恢复，不依赖对端重复发送数据。

## 依赖与部署兼容性

`Cargo.toml` 与 `Cargo.lock` 固定 quiche 提交 `4043cb6d372a43bc61806fa983b434e5f9e3997b`（`vilicvane/quiche` 的 `tcp-ack-recovery` 分支）。构建直接获取该 Git revision，不需要相邻的本地工作树。
