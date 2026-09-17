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
  /** 服务端拒绝任何二进制 WebSocket 帧 —— 大文件一律走 HTTP，避免单连接阻塞事件循环与内存 */
  rejectBinaryWs: process.env.REJECT_BINARY_WS !== '0',

  // 消息
  maxContentLength: Number(process.env.MAX_CONTENT_LENGTH || 4_000), // 文本消息最大字符数
  syncBatchSize: Number(process.env.SYNC_BATCH_SIZE || 500), // 断线补发单批最大条数
  historyMaxLimit: Number(process.env.HISTORY_MAX_LIMIT || 100), // 历史消息单次拉取上限
  recallWindowMs: Number(process.env.RECALL_WINDOW_MS ?? 2 * 60_000), // 发起者撤回时限（默认 2 分钟）；-1 = 不限时
  quoteWindowSeq: Number(process.env.QUOTE_WINDOW_SEQ || 5000), // 引用的目标消息距今不能超过该 seq 距离

  // 发送限流（令牌桶，按用户）
  rateLimitPerSec: Number(process.env.RATE_LIMIT_PER_SEC || 10),
  rateLimitBurst: Number(process.env.RATE_LIMIT_BURST || 20),

  // —— 富媒体 / 上传 ——
  storageDir: process.env.STORAGE_DIR || 'storage', // 已完成资产目录
  chunkDir: process.env.CHUNK_DIR || 'chunks', // 未完成上传的临时分片目录
  maxFileSize: Number(process.env.MAX_FILE_SIZE || 500 * 1024 * 1024), // 单文件上限（默认 500MB）
  chunkSize: Number(process.env.CHUNK_SIZE || 1024 * 1024), // 建议分片大小（默认 1MB）
  chunkMinSize: Number(process.env.CHUNK_MIN_SIZE || 64 * 1024), // 服务端接受的最小分片
  chunkMaxSize: Number(process.env.CHUNK_MAX_SIZE || 16 * 1024 * 1024), // 服务端接受的最大分片
  maxUploadConcurrencyPerUser: Number(process.env.MAX_UPLOAD_CONCURRENCY_PER_USER || 4), // 每用户进行中上传任务上限
  /** 已完成但长期未被任何消息引用的资产，多久后物理删除（默认 7 天）；0 = 永久保留完成态资产 */
  assetTtlMs: Number(process.env.ASSET_TTL_MS ?? 7 * 24 * 3600_000),
  /** 未完成上传任务（含临时分片）的保留时长，超时由清理任务删除 */
  uploadTtlMs: Number(process.env.UPLOAD_TTL_MS || 24 * 3600_000),
  cleanupIntervalMs: Number(process.env.CLEANUP_INTERVAL_MS || 15 * 60_000),
  /** 病毒扫描模式：off 直通；mocked 用可注入判定函数（默认 EICAR 判定）；clamav 走 INSTREAM 协议 */
  virusScanMode: process.env.VIRUS_SCAN_MODE || 'mocked',
  virusScanHost: process.env.VIRUS_SCAN_HOST || '127.0.0.1',
  virusScanPort: Number(process.env.VIRUS_SCAN_PORT || 3310),
  /** 扫描器自身故障（连不上 ClamAV 等）时是否阻断上传完成。true=故障关闭（fail-closed，默认） */
  virusFailClosed: process.env.VIRUS_FAIL_CLOSED !== '0',
  /** 撤回后若该资产无其他消息引用，是否物理删除资产文件 */
  deleteAssetOnRecall: process.env.DELETE_ASSET_ON_RECALL !== '0',

  // 演示用鉴权：token 签名密钥（生产环境务必替换）
  authSecret: process.env.AUTH_SECRET || 'dev-secret-change-me',
};
