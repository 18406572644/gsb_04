'use strict';

/**
 * 全局配置。全部支持环境变量覆盖，便于测试与部署。
 */
module.exports = {
  // 服务监听
  port: Number(process.env.PORT || 8080),
  host: process.env.HOST || '0.0.0.0',

  // SQLite 文件路径，':memory:' 仅用于测试
  dbPath: process.env.CHAT_DB_PATH || 'chat.db',

  // 连接管理
  maxConnections: Number(process.env.MAX_CONNECTIONS || 1000), // 全局最大并发连接
  maxConnectionsPerUser: Number(process.env.MAX_CONNECTIONS_PER_USER || 3), // 单用户最大连接（多端）
  heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS || 30_000), // ping 周期
  heartbeatTimeoutMs: Number(process.env.HEARTBEAT_TIMEOUT_MS || 75_000), // 超过该时长无 pong 判定死亡

  // 可靠投递
  ackResendIntervalMs: Number(process.env.ACK_RESEND_INTERVAL_MS || 2_000), // 未 ACK 重发扫描周期
  ackResendAfterMs: Number(process.env.ACK_RESEND_AFTER_MS || 3_000), // 发送后多久未收到 ACK 触发重发
  ackMaxResend: Number(process.env.ACK_MAX_RESEND || 5), // 单条消息最大重发次数，超限断开连接
  maxUnackedPerConn: Number(process.env.MAX_UNACKED_PER_CONN || 1_000), // 单连接未 ACK 积压上限（背压）

  // 消息
  maxContentLength: Number(process.env.MAX_CONTENT_LENGTH || 4_000), // 单条消息最大字符数
  syncBatchSize: Number(process.env.SYNC_BATCH_SIZE || 500), // 断线补发单批最大条数
  historyMaxLimit: Number(process.env.HISTORY_MAX_LIMIT || 100), // 历史消息单次拉取上限

  // 发送限流（令牌桶，按用户）
  rateLimitPerSec: Number(process.env.RATE_LIMIT_PER_SEC || 10),
  rateLimitBurst: Number(process.env.RATE_LIMIT_BURST || 20),

  // WebSocket 富媒体隔离：控制面帧硬上限（超限 1009）与发送缓冲水位
  wsMaxPayload: Number(process.env.WS_MAX_PAYLOAD || 65_536),
  wsBufferedSoft: Number(process.env.WS_BUFFERED_SOFT || 2_097_152), // 软水位：track 但暂缓 write，等重发
  wsBufferedHard: Number(process.env.WS_BUFFERED_HARD || 8_388_608), // 硬水位：close 1013

  // 富媒体存储
  storageRoot: process.env.STORAGE_ROOT || 'uploads', // tmp/blob/quarantine 根目录
  maxImageSize: Number(process.env.MAX_IMAGE_SIZE || 10_485_760), // 10MiB
  maxVoiceSize: Number(process.env.MAX_VOICE_SIZE || 20_971_520), // 20MiB
  maxFileSize: Number(process.env.MAX_FILE_SIZE || 104_857_600), // 100MiB
  uploadChunkSize: Number(process.env.UPLOAD_CHUNK_SIZE || 1_048_576), // 默认/建议片长 1MiB
  uploadChunkMin: Number(process.env.UPLOAD_CHUNK_MIN || 65_536),
  uploadChunkMax: Number(process.env.UPLOAD_CHUNK_MAX || 16_777_216),
  maxConcurrentUploads: Number(process.env.MAX_CONCURRENT_UPLOADS || 4), // 每用户活跃任务数
  chunkIdleTimeoutMs: Number(process.env.CHUNK_IDLE_TIMEOUT_MS || 30_000), // 分片无数据传输超时

  // 过期清理
  uploadTaskTtlMs: Number(process.env.UPLOAD_TASK_TTL_MS || 86_400_000), // 未完成任务/分片 24h
  orphanAssetTtlMs: Number(process.env.ORPHAN_ASSET_TTL_MS || 86_400_000), // complete 后无消息引用 24h
  quarantineTtlMs: Number(process.env.QUARANTINE_TTL_MS || 604_800_000), // 隔离区 7d
  completedBlobGraceMs: Number(process.env.COMPLETED_BLOB_GRACE_MS || 3_600_000), // ready 任务宽限 1h
  reapIntervalMs: Number(process.env.REAP_INTERVAL_MS || 600_000), // reaper 周期；0 关闭

  // 病毒/内容扫描
  scannerMode: process.env.SCANNER_MODE || 'builtin', // off | builtin | clamd
  scannerFailPolicy: process.env.SCANNER_FAIL_POLICY || 'closed', // clamd 不可用：open | closed
  clamdHost: process.env.CLAMD_HOST || '127.0.0.1',
  clamdPort: Number(process.env.CLAMD_PORT || 3310),
  clamdSocket: process.env.CLAMD_SOCKET || '', // 非空时优先用 unix socket
  clamdTimeoutMs: Number(process.env.CLAMD_TIMEOUT_MS || 5_000),
  blockedExtensions: (process.env.BLOCKED_EXTENSIONS
    || 'exe,scr,bat,cmd,com,pif,msi,msp,ps1,vbs,js,jar,app,dll,sh,lnk,cpl,reg')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
  allowedImageMime: (process.env.ALLOWED_IMAGE_MIME
    || 'image/png,image/jpeg,image/gif,image/webp')
    .split(',').map((s) => s.trim()).filter(Boolean),
  allowedVoiceMime: (process.env.ALLOWED_VOICE_MIME
    || 'audio/webm,audio/ogg,audio/mp4')
    .split(',').map((s) => s.trim()).filter(Boolean),

  // 富媒体消息
  assetTicketTtlMs: Number(process.env.ASSET_TICKET_TTL_MS || 120_000), // 下载票有效期
  recallWindowMs: Number(process.env.RECALL_WINDOW_MS || 300_000), // 普通成员撤回窗 5min
  captionMaxLength: Number(process.env.CAPTION_MAX_LENGTH || 1_000),

  // 演示用鉴权：token 签名密钥（生产环境务必替换）
  authSecret: process.env.AUTH_SECRET || 'dev-secret-change-me',
};
