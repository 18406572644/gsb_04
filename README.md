# 可靠消息聊天室（Node + ws + SQLite）· 富媒体版

基于 WebSocket 的可靠消息投递聊天室。不引入 MQ，以 SQLite 为唯一持久化设施，实现：

- **消息不丢失**：先落库、再 ACK、后广播；服务重启后消息完整可补发
- **ACK 确认**：双向确认 —— 发送方收服务端 ACK（含分配的 seq）；接收方对推送做累积 ACK
- **断线补发**：重连后按 `lastSeq` 增量回放缺口，分批拉取
- **幂等去重**：`clientMsgId` 唯一约束防发送重试产生重复；客户端按 `seq` 过滤重复投递
- **消息时序可控**：每房间单调递增 `seq`，由计数器在写事务内分配，保证房间内全序
- **连接管理**：心跳保活、全局/单用户连接数上限、背压断开、优雅退出
- **房间权限**：管理员 / 成员 / 禁言三种状态，管理员可禁言、解禁
- **发送限流**：按用户令牌桶
- **富媒体消息**：图片 / 文件 / 语音三类消息，全链路「HTTP 上传任务 → 病毒扫描 →
  消息状态确认 → 按权限下载」，大文件绝不经过 WebSocket

## 快速开始

```bash
npm install
npm start          # http://localhost:8080
npm test           # 30 个集成测试（13 文本协议 + 17 富媒体）
```

浏览器打开 `http://localhost:8080`，用不同昵称开两个标签页即可体验（建房、发消息、
发图片/文件/语音、引用、撤回、禁言管理）。断网/刷新页面后自动重连并补发离线期间的消息。

要求 Node.js ≥ 22.13（使用内置 `node:sqlite`，唯一第三方依赖是 `ws`）。

## 架构

```
src/
├── config.js    配置（端口、连接上限、心跳、重发、限流、上传/扫描/TTL，均可环境变量覆盖）
├── db.js        SQLite 持久层：schema、幂等写入、seq、游标、资产/上传任务/下载审计
├── hub.js       连接注册中心：房间索引、广播、未 ACK 追踪、心跳/重发扫描
├── storage.js   本地对象存储：分块落盘、流式合并（sha256/大小校验）、流式下载、GC
├── scanner.js   病毒扫描：off / mocked(EICAR) / ClamAV(INSTREAM)，三态判定 + fail-closed
├── uploads.js   上传任务服务：init/chunk/complete、断点续传、秒传去重、扫描处置
├── server.js    HTTP（登录/上传/下载/静态）+ WS（消息路由、权限、撤回、背压、生命周期）
└── util.js      token 签名、帧解析等工具
public/index.html   演示客户端（可靠投递协议 + 分片上传 + 图片/语音内联 + 引用/撤回）
test/chat.test.js    文本协议集成测试（13）
test/media.test.js   富媒体全链路集成测试（17）
```

### 两阶段发送（核心架构决策）

大文件**不经过 WebSocket**。WS 帧有 64KB 硬上限（`maxPayload`，超限 1009 断开），
二进制帧直接拒绝 —— 杜绝单连接被巨型帧缓冲占满内存、阻塞同连接文本收发的背压问题。

```
阶段一：上传任务执行（HTTP，可中断/续传）
  POST /api/uploads                 init   声明 {filename,kind,mime,size,sha256,chunkSize}
  PUT  /api/uploads/:id/chunks/:idx        分片（流式直落临时目录，不整文件进内存）
  POST /api/uploads/:id/complete           合并 → 大小/sha256 校验 → 病毒扫描 → ready

阶段二：消息状态确认（WebSocket，轻量 JSON 帧）
  client → {type:'media', roomId, clientMsgId, assetId, caption?, quoteSeq?}
  server 校验资产 status=ready → 事务内分配 seq 落库 → ACK → 房间广播
  接收端按 msg.asset.id + 自身权限走 HTTP 下载（消息帧不含任何文件字节）
```

**只有上传完成（合并校验通过 + 病毒扫描干净）后消息才允许落库**；资产处于
`scanning / scan_error / infected / deleted` 时媒体消息分别被拒（ASSET_NOT_READY /
SCAN_UNAVAILABLE / VIRUS_DETECTED / ASSET_GONE）。

### 数据模型

| 表 | 说明 |
|---|---|
| `users` | 用户（演示级 token 认证） |
| `rooms` | 房间，`last_seq` 为房间消息序号计数器 |
| `members` | 成员关系：`role`（admin/member）+ `muted_until`；**退出房间即删行，立即丧失下载权限** |
| `messages` | 多态消息：`msg_type`(text/image/file/voice) + `asset_id` + `quote_seq` + `recalled` 墓碑；主键 `(room_id, seq)`，幂等键 `(room_id, sender_id, client_msg_id)` |
| `cursors` | 每用户每房间已确认游标 `last_ack_seq` |
| `assets` | 内容寻址资源：`sha256` 全局唯一（天然去重/秒传）、`status`(scanning/ready/infected/scan_error/deleted)、文件名/大小/MIME/上传者；deleted 为墓碑（审计留痕） |
| `upload_tasks` | 上传任务：open/completed/expired。同用户同 hash 仅一个 open 任务（中断续传的锚点）；秒传复用会写一条 completed 凭证 |
| `upload_chunks` | 已收分片登记（idx + size），断点续传时下发 `received` 列表 |
| `asset_downloads` | 下载审计（谁、何时、哪个房间、多少字节） |

旧库平滑升级：启动时自动 `ALTER TABLE` 补齐 messages 新列。

### 去重（三层）

1. **WS 消息幂等**：`clientMsgId` 唯一约束，重试只回原 ACK，不重复落库/广播；
2. **内容秒传**：`assets.sha256` UNIQUE，同内容 init 直接返回 `{reused:true, assetId}`，
   零字节；跨用户同样成立（写一条 completed 凭证作为来源审计）；
3. **任务级续传锚点**：`(uploader_id, sha256) WHERE status='open'` 部分唯一索引，
   中断后重新 init 找回同一任务，按 `received` 只补缺失分片。同 idx 重传幂等覆盖。

### 病毒扫描处置

判定三态严格区分：`clean` / `infected`（有毒）/ `error`（扫描器自身故障）。

- **感染**：删除物理对象、资产置 `infected`（**hash 拉黑**：换文件名/换房间重传一律
  422 VIRUS_DETECTED）、清分片、complete 失败、媒体消息永不允许落库；
- **扫描器故障**：按 `VIRUS_FAIL_CLOSED`（默认开）阻断 —— complete 返回 502
  SCAN_UNAVAILABLE，**任务保持 open**，扫描恢复后重试 complete 即可，无需重传字节；
- ClamAV 模式走 clamd `INSTREAM` 协议（流式分块，≤64KB/块）；mocked 模式命中 EICAR
  测试签名即判感染（测试用），也支持注入判定函数。

### 撤回与文件删除规则

- 仅发送者本人可撤回，默认 2 分钟窗口（`RECALL_WINDOW_MS`，-1 不限）；
- 撤回写墓碑（recalled=1）并广播 `recalled` 帧（走 ACK 追踪，漏收端重连补发时也会
  从 DB 拿到墓碑）；下发的撤回消息剥除正文与资产信息；
- **文件删除按实时引用计数判定**：撤回后若该资产已无任何「未撤回消息」引用（跨房间
  统计），物理删除文件并置 tombstone；仍被其他消息引用则保留。引用计数由查询实时
  推导而非维护计数器，无计数漂移；
- 先删文件成功再置 deleted；删除失败保持 ready，由 TTL GC 兜底。

### 下载权限管控

`GET /api/assets/:id/download`（Bearer token 或 `?token=`）要求**同时**满足：

1. 用户当前是引用该资产的某房间成员（`members` 行存在）；
2. 该房间存在一条引用此资产的**未撤回**消息。

因此：退出房间（成员行删除）→ 403；消息全部撤回 → 403；非成员 → 403；未认证 → 401；
资产 deleted/TTL 清理 → 410；感染 → 422。下载为流式（支持 `Range` 断点续传、206），
`file` 类强制 `Content-Disposition: attachment` 并带 `nosniff` + 严格 CSP，
`image/voice` 允许 inline（类型白名单已限定）。每次完成写下载审计。

### 过期清理（cleanupSweep，默认 15 分钟）

1. open 上传任务超过 `UPLOAD_TTL_MS`（默认 24h）→ 置 expired + 删临时分片；
2. ready 资产超过 `ASSET_TTL_MS`（默认 7 天）且无未撤回消息引用 → 物理删除 + 墓碑；
3. scan_error 资产超过任务 TTL（重试窗口已过）→ 回收物理文件（行保留，同 hash
   重传时自动重置重扫）；
4. 启动时及定时清理崩溃残留的 `*.tmp-*` 文件（分片/合并中间产物）。

### 内存与背压

- 上传：分片流式直落磁盘（pipeline + Transform 计数/哈希），合并用异步生成器
  单遍流式拼接，**服务器内存占用与文件大小无关**；
- 下载：`createReadStream` + Range，按 TCP 背压；
- WS：64KB maxPayload + 二进制帧拒绝 + 单连接未 ACK 积压上限（超限断开，重连补发），
  大文件通道与消息通道彻底隔离。

## 协议

### WebSocket 客户端 → 服务端

| 类型 | 字段 | 说明 |
|---|---|---|
| `ping` | `t` | 心跳，回 `pong` |
| `create_room` | `name` | 建房，创建者为管理员 |
| `join` | `room, lastSeq?` | 加入/重连加入，带进度立即补发 |
| `leave` | `roomId` | **退出房间（删除成员关系，丧失下载权限）** |
| `msg` | `roomId, clientMsgId, content, quoteSeq?` | 文本消息 |
| `media` | `roomId, clientMsgId, assetId, content?, quoteSeq?` | 富媒体消息（阶段二，帧内无字节） |
| `recall` | `roomId, seq` | 撤回本人消息（窗口内） |
| `ack` | `roomId, seq` | 累积确认 |
| `sync` | `roomId, lastSeq?` | 请求补发 |
| `history` | `roomId, beforeSeq?, limit?` | 历史翻页（升序） |
| `rooms` / `members` | — | 房间列表 / 成员列表 |
| `mute` / `unmute` | `roomId, userId, minutes?` | 管理员禁言/解禁 |

### WebSocket 服务端 → 客户端

| 类型 | 说明 |
|---|---|
| `welcome` | `{userId, name, serverTime, upload:{maxFileSize, chunkSize, kinds}}` |
| `joined` | 入房成功 |
| `msg` | 多态消息：`{seq, clientMsgId, from, fromName, msgType, content, ts, asset?, quote?, recalled?}` |
| `ack` | 发送确认（文本/媒体共用） |
| `recalled` | `{roomId, seq}` 撤回墓碑 |
| `sync_done` / `history` / `rooms` / `members` / `notice` | 同前 |
| `error` | `{code, message, ref?}` |
| `server_shutdown` | 服务即将关闭 |

`asset` 形如 `{id,name,size,mime,kind}`（ready 时）或 `{id,gone:true}`；`quote` 为一层
摘要 `{seq,from,fromName,msgType,content?,asset?}`，目标已撤回时为 `{seq,recalled:true}`。

新增错误码：`ASSET_NOT_FOUND` `ASSET_NOT_READY` `ASSET_GONE` `VIRUS_DETECTED`
`SCAN_UNAVAILABLE` `QUOTE_NOT_FOUND` `QUOTE_TOO_OLD` `RECALL_WINDOW_EXPIRED`
`NOT_FOUND`。

### HTTP

| 方法/路径 | 说明 |
|---|---|
| `POST /api/login` | 演示登录，返回 token |
| `POST /api/uploads` | init：`{filename,kind,mime,size,sha256,chunkSize}` → 201 任务（含 `taskId,chunkSize,totalChunks,received[]`）或 200 `{reused:true,assetId}` 秒传 |
| `PUT /api/uploads/:taskId/chunks/:idx` | 上传分片（原始字节 body），返回累计 `received` |
| `POST /api/uploads/:taskId/complete` | 合并+校验+扫描 → `{assetId,status:'ready'}` |
| `GET /api/uploads/:taskId` | 查询任务状态/已收分片 |
| `POST /api/uploads/:taskId/abort` | 放弃上传 |
| `GET /api/assets/:id/download` | 按权限流式下载（Range、审计） |

上传错误码（HTTP 状态）：`FILE_TOO_LARGE`(413) `UNSUPPORTED_TYPE`(400)
`CHUNK_SIZE_MISMATCH`(400) `MISSING_CHUNKS`(409, details.missing)
`INTEGRITY_CHECK_FAILED`(422) `VIRUS_DETECTED`(422) `SCAN_UNAVAILABLE`(502)
`TOO_MANY_UPLOADS`(429) `UPLOAD_NOT_OPEN`(409) `NO_SUCH_UPLOAD`(404)。

### 连接建立

```
POST /api/login {"name":"alice"}  →  {userId, name, token}
GET  /ws?token=<token>            →  WebSocket 升级
```

## 关键配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `8080` / `0.0.0.0` | 监听地址 |
| `CHAT_DB_PATH` | `chat.db` | SQLite 路径（`:memory:` 用于测试） |
| `STORAGE_DIR` / `CHUNK_DIR` | `storage` / `chunks` | 对象目录 / 临时分片目录 |
| `MAX_FILE_SIZE` | `524288000` | 单文件上限 500MB |
| `CHUNK_SIZE` / `CHUNK_MIN_SIZE` / `CHUNK_MAX_SIZE` | `1MB` / `64KB` / `16MB` | 建议/允许分片大小 |
| `MAX_UPLOAD_CONCURRENCY_PER_USER` | `4` | 每用户进行中上传任务上限 |
| `ASSET_TTL_MS` | `7d` | 无引用完成资产保留期（0=永久） |
| `UPLOAD_TTL_MS` | `24h` | 未完成任务/scan_error 保留期 |
| `CLEANUP_INTERVAL_MS` | `15m` | GC 周期（0=关闭） |
| `VIRUS_SCAN_MODE` | `mocked` | `off` / `mocked` / `clamav` |
| `VIRUS_SCAN_HOST` / `VIRUS_SCAN_PORT` | `127.0.0.1` / `3310` | clamd 地址 |
| `VIRUS_FAIL_CLOSED` | `1` | 扫描器故障时阻断完成（0=放行留痕） |
| `DELETE_ASSET_ON_RECALL` | `1` | 撤回后无引用即删文件 |
| `RECALL_WINDOW_MS` | `120000` | 撤回时限（-1 不限） |
| `REJECT_BINARY_WS` | `1` | 拒绝 WS 二进制帧 |
| `MAX_CONNECTIONS` / `MAX_CONNECTIONS_PER_USER` | `1000` / `3` | 连接上限 |
| `HEARTBEAT_INTERVAL_MS` / `HEARTBEAT_TIMEOUT_MS` | `30000` / `75000` | 心跳 |
| `ACK_RESEND_AFTER_MS` / `ACK_MAX_RESEND` / `MAX_UNACKED_PER_CONN` | `3000` / `5` / `1000` | 重发与背压 |
| `RATE_LIMIT_PER_SEC` / `RATE_LIMIT_BURST` | `10` / `20` | 发送限流（文本/媒体共用） |
| `AUTH_SECRET` | — | token HMAC 密钥，**生产必须设置** |

## 已知边界（演示级取舍）

- 认证为演示级（用户名即账号、HMAC token），生产应替换为正式账号体系；
- 本地文件系统对象存储，接口形状对齐 S3/OSS，可替换实现（PUT/GET/DELETE 三个原语）；
- ClamAV 为唯一内置扫描适配器，其他引擎实现 `scanFile(filePath)` 三态即可接入；
- 单进程架构，多实例部署需引入外部 Pub/Sub 做跨节点广播与共享对象存储（DB 层无需改动）；
- 秒传意味着「知道 sha256 即可在 init 阶段零字节获得发送权」——对封闭 IM 可接受，
  公开网盘场景应改为「秒传仅下载、发送仍需持有授权」。
