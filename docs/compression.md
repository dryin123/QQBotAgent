# 上下文压缩算法说明

## 背景与动机

QQ 群/单聊消息不限轮数累积，会话上下文（history）会无限增长，超出大模型上下文窗口后：

- 请求体过大导致 API 报错或费用激增；
- 超出部分被静默截断，丢失早期关键信息。

本项目在 `SessionManager` 中实现了**本地分组滚动压缩**：

1. 按 `user_id + group_id` 分组维护会话；
2. 每收到一条消息先估算该组历史 token 总量；
3. 超限（`compression_token_limit`，默认 60000）时，把当前组历史交给大模型生成中文摘要，存为 `history_temp/<uid>_g<group>/compress_NNN.txt`；
4. 清空当前组 history 开始新轮次，后续 `get_context` 会把历史摘要以 system 消息注入上下文。

## Token 估算

`_estimate_tokens` 采用中英混合启发式（无外部 tokenizer 依赖）：

- ASCII 字符：约 4 字符 / token；
- 中文/全角字符：约 0.75 token / 字；
- 每条消息固定 +10 系统开销。

精度足够用于压缩阈值判定；如需精确计费请以 API 返回的 usage 为准。

## 触发策略

- 检查在收到每条消息时执行（`maybe_compress`），**压缩任务本身在后台执行**（`asyncio.create_task`），不阻塞当条消息的回复；
- `_compressing` 防重入标志保证同一时刻只有一个压缩任务在跑；
- 压缩完成后 history 清空、token 大幅回落，天然避免短时间内重复触发。

## 压缩质量保障

- 压缩 prompt 明确要求保留：用户偏好、进行中的任务、重要决定、待办事项；
- 摘要目标长度约 `max(500, compression_token_limit // 20)` token；
- 多轮压缩会产生多个 `compress_NNN.txt`，新上下文按序号依次注入（信息逐层衰减是已知特性，可在 WebUI 关闭压缩改用更多轮的原始保留）。

## 阈值调优指南

| 场景 | 建议 |
|---|---|
| 追求省钱、对话短平快 | 开激进：`compression_token_limit` 调低（如 20000~30000） |
| 长任务需要完整上下文 | 调高（如 80000+）或关闭自动压缩 |
| 中文为主 | 默认启发式已按中文字加权，无需调整 |
