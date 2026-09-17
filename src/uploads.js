'use strict';

const { randomId, now } = require('./util');

class HttpError extends Error {
  constructor(status, code, message, details = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const KIND_MIME = {
  image: (m) => /^image\/(jpeg|png|gif|webp|bmp)$/i.test(m),
  voice: (m) => /^audio\//i.test(m),
  file: () => true, // 通用文件：类型不限，由病毒扫描兜底
};

/**
 * 上传任务执行（两阶段发送的「阶段一」）。
 *
 * init（声明）→ chunk（分块流式落盘，可中断、可重传）→ complete（合并 + 完整性校验 +
 * 病毒扫描）。全流程通过 sha256 内容寻址去重：同内容秒传；同用户同内容只允许一个
 * open 任务，中断后重新 init 即返回原任务与缺失分片列表实现断点续传。
 */
class UploadService {
  constructor({ db, storage, scanner, config }) {
    this.db = db;
    this.storage = storage;
    this.scanner = scanner;
    this.config = config;
  }

  // ------------------------------------------------------------- 阶段 1a：init

  async init(user, body) {
    const filename = typeof body.filename === 'string' ? body.filename.trim() : '';
    const { kind, mime } = body;
    const size = Number(body.size);
    const sha256 = typeof body.sha256 === 'string' ? body.sha256.toLowerCase() : '';

    if (!filename || filename.length > 255) throw new HttpError(400, 'BAD_REQUEST', 'invalid filename');
    if (!KIND_MIME[kind]) throw new HttpError(400, 'BAD_REQUEST', 'kind must be image/file/voice');
    if (typeof mime !== 'string' || mime.length > 128 || !KIND_MIME[kind](mime)) {
      throw new HttpError(400, 'UNSUPPORTED_TYPE', `unsupported mime for ${kind}: ${mime}`);
    }
    if (!Number.isInteger(size) || size <= 0 || size > this.config.maxFileSize) {
      throw new HttpError(413, 'FILE_TOO_LARGE', `size must be 1..${this.config.maxFileSize}`);
    }
    if (!/^[0-9a-f]{64}$/.test(sha256)) throw new HttpError(400, 'BAD_REQUEST', 'invalid sha256');
    if (filename.includes('\0')) throw new HttpError(400, 'BAD_REQUEST', 'invalid filename');

    // —— 去重 1：内容已存在 ——
    let asset = this.db.getAssetBySha(sha256);
    if (asset) {
      if (asset.status === 'ready') {
        // 秒传：无需再传字节。先确认物理对象还在（防 DB/磁盘不一致）
        if (await this.storage.objectExists(sha256)) {
          // 为非上传者补一条完成态凭证，使其有权把该内容作为媒体消息发送（审计可溯源）
          if (asset.uploader_id !== user.id && !this.db.hasCompletedUpload(user.id, sha256)) {
            this.db.insertCompletedTask({
              id: randomId('up_'), uploaderId: user.id, assetId: asset.id,
              filename, kind, mime, size, sha256,
            });
          }
          return { reused: true, assetId: asset.id, status: 'ready' };
        }
        // 行在但文件丢了：落到下方重置后重传
      } else if (asset.status === 'infected') {
        // hash 拉黑：病毒文件换名字/换房间重传一律拒绝
        throw new HttpError(422, 'VIRUS_DETECTED', `infected content blocked: ${asset.scan_info}`);
      }
      // scan_error / deleted（文件丢失）→ 重置资产行，走完整重传重扫
      if (asset.status !== 'ready') {
        asset = this.db.resetAssetForReupload(asset.id, {
          size, mime, filename, kind, uploaderId: user.id,
        });
      }
    }

    // —— 去重 2：同用户同内容有未完成任务 → 断点续传 ——
    const open = this.db.findOpenTask(user.id, sha256);
    if (open) return this._taskView(open, /*resume*/ true);

    if (this.db.countOpenTasks(user.id) >= this.config.maxUploadConcurrencyPerUser) {
      throw new HttpError(429, 'TOO_MANY_UPLOADS', 'too many concurrent uploads, finish or abort one');
    }

    // 服务端权威分片大小：客户端建议值会被夹到允许区间，客户端必须按返回值切分
    const chunkSize = Math.min(
      this.config.chunkMaxSize,
      Math.max(this.config.chunkMinSize, Number(body.chunkSize) || this.config.chunkSize)
    );
    const totalChunks = Math.ceil(size / chunkSize);

    const taskId = randomId('up_');
    if (!asset) {
      const assetId = randomId('as_');
      asset = this.db.createAsset({
        id: assetId,
        sha256,
        size,
        mime,
        filename,
        kind,
        uploaderId: user.id,
        storagePath: '',
        status: 'scanning',
      });
    }
    const task = this.db.createTask({
      id: taskId,
      uploaderId: user.id,
      filename,
      kind,
      mime,
      size,
      sha256,
      chunkSize,
      totalChunks,
    });
    return this._taskView(task, false);
  }

  // ------------------------------------------------------------- 阶段 1b：chunk

  /**
   * 流式写入一个分片。幂等：同一 idx 重传直接覆盖（断在中途的半截分片也能被重传修复）。
   * @param rawLen 声明的 Content-Length，用来和该 idx 的期望字节数比对
   */
  async putChunk(user, taskId, idx, req, rawLen) {
    const task = this._requireOpenTask(user, taskId);
    if (!Number.isInteger(idx) || idx < 0 || idx >= task.total_chunks) {
      throw new HttpError(400, 'BAD_REQUEST', `chunk idx must be 0..${task.total_chunks - 1}`);
    }
    const expected = idx === task.total_chunks - 1
      ? task.size - (task.total_chunks - 1) * task.chunk_size
      : task.chunk_size;
    if (Number.isInteger(rawLen) && rawLen !== expected) {
      req.resume(); // 排空请求体，避免影响同连接后续请求（HTTP keep-alive）
      throw new HttpError(400, 'CHUNK_SIZE_MISMATCH', `chunk ${idx} expects ${expected} bytes, got ${rawLen}`);
    }

    // 边收边落盘边校验该分片大小（读侧造假 Content-Length 也兜得住）
    let written;
    try {
      written = await this.storage.putChunk(taskId, idx, req, { maxSize: expected });
    } catch (err) {
      if (/exceeds declared size/.test(err.message)) {
        req.destroy();
        throw new HttpError(400, 'CHUNK_TOO_LARGE', `chunk ${idx} exceeds ${expected} bytes`);
      }
      throw err;
    }
    const { size } = written;
    if (size !== expected) {
      throw new HttpError(400, 'CHUNK_SIZE_MISMATCH', `chunk ${idx} expects ${expected} bytes, got ${size}`);
    }
    this.db.putChunk(taskId, idx, size);
    return { ok: true, idx, size, received: this.db.receivedChunkIdx(taskId) };
  }

  // ------------------------------------------------------------- 阶段 1c：complete

  async complete(user, taskId) {
    const task = this._requireOpenTask(user, taskId);
    // 以磁盘为准：DB 登记与临时目录可能因外部清理/崩溃不一致，先对齐再判缺失
    const onDisk = new Set(await this.storage.listChunks(taskId));
    for (const idx of this.db.receivedChunkIdx(taskId)) {
      if (!onDisk.has(idx)) this.db.deleteChunk(taskId, idx);
    }
    const missing = [];
    for (let i = 0; i < task.total_chunks; i++) if (!onDisk.has(i)) missing.push(i);
    if (missing.length) {
      throw new HttpError(409, 'MISSING_CHUNKS', 'upload incomplete', { missing });
    }

    let asset = this.db.getAssetBySha(task.sha256);
    if (!asset) {
      // 理论不可达（init 已建行），防御性补建
      asset = this.db.createAsset({
        id: randomId('as_'), sha256: task.sha256, size: task.size, mime: task.mime,
        filename: task.filename, kind: task.kind, uploaderId: user.id,
        storagePath: '', status: 'scanning',
      });
    }

    // 已 ready（例如别的端秒传后此任务才 complete）——幂等成功
    if (asset.status === 'ready' && await this.storage.objectExists(task.sha256)) {
      this.db.completeTask(task.id, asset.id);
      await this.storage.deleteChunks(task.id);
      this.db.deleteChunks(task.id);
      return { assetId: asset.id, status: 'ready', reused: true };
    }

    // 合并 + 大小/sha256 校验（流式，不按文件大小占内存）
    let objectPath;
    try {
      objectPath = await this.storage.mergeChunks(task, { sha256: task.sha256, size: task.size });
    } catch (err) {
      throw new HttpError(422, 'INTEGRITY_CHECK_FAILED', err.message);
    }

    // —— 病毒扫描（合并出的正式对象先扫，决定去留）——
    const verdict = this.scanner.applyFailurePolicy(
      await this.scanner.scanFile(objectPath, asset)
    );

    if (verdict.verdict === 'infected') {
      // 病毒处置：物理删除对象、hash 拉黑（asset 行保留为 infected），分片清掉；消息永不允许落库
      await this.storage.deleteObject(task.sha256);
      await this.storage.deleteChunks(task.id);
      this.db.deleteChunks(task.id);
      this.db.setAssetStatus(asset.id, 'infected', verdict.signature || 'infected');
      this.db.completeTask(task.id, asset.id);
      throw new HttpError(422, 'VIRUS_DETECTED', `infected: ${verdict.signature || ''}`.trim());
    }

    if (verdict.verdict === 'error') {
      // 扫描器故障 + fail-closed：任务保持 open 允许稍后重试 complete（对象保留待重扫）
      this.db.setAssetStatus(asset.id, 'scan_error', verdict.error || 'scan error');
      throw new HttpError(502, 'SCAN_UNAVAILABLE', verdict.error || 'scanner unavailable; retry later');
    }

    // clean
    const ready = this.db.setAssetReady(asset.id);
    this.db.completeTask(task.id, asset.id);
    await this.storage.deleteChunks(task.id);
    this.db.deleteChunks(task.id);
    return { assetId: ready.id, status: 'ready', warned: !!verdict.warned };
  }

  getStatus(user, taskId) {
    const task = this.db.getTask(taskId);
    if (!task || task.uploader_id !== user.id) {
      throw new HttpError(404, 'NO_SUCH_UPLOAD', 'upload task not found');
    }
    return this._taskView(task, task.status === 'open');
  }

  /** 放弃上传：任务置过期 + 删临时分片 */
  async abort(user, taskId) {
    const task = this.db.getTask(taskId);
    if (!task || task.uploader_id !== user.id) {
      throw new HttpError(404, 'NO_SUCH_UPLOAD', 'upload task not found');
    }
    if (task.status === 'open') this.db.expireTask(task.id);
    await this.storage.deleteChunks(task.id);
    this.db.deleteChunks(task.id);
    return { ok: true };
  }

  // ------------------------------------------------------------- 清理任务

  /** 过期未完成上传：标记 + 删除临时分片，返回清理条数 */
  async sweepStaleTasks() {
    const cutoff = now() - this.config.uploadTtlMs;
    let swept = 0;
    for (const task of this.db.findStaleOpenTasks(cutoff, 200)) {
      if (this.db.expireTask(task.id)) {
        await this.storage.deleteChunks(task.id);
        this.db.deleteChunks(task.id);
        swept++;
      }
    }
    return swept;
  }

  // ------------------------------------------------------------- 内部

  _requireOpenTask(user, taskId) {
    const task = this.db.getTask(taskId);
    if (!task || task.uploader_id !== user.id) {
      throw new HttpError(404, 'NO_SUCH_UPLOAD', 'upload task not found');
    }
    if (task.status !== 'open') {
      throw new HttpError(409, 'UPLOAD_NOT_OPEN', `upload already ${task.status}`);
    }
    return task;
  }

  _taskView(task, resume) {
    return {
      taskId: task.id,
      assetId: task.asset_id,
      status: task.status,
      resumed: resume,
      filename: task.filename,
      kind: task.kind,
      size: task.size,
      sha256: task.sha256,
      chunkSize: task.chunk_size,
      totalChunks: task.total_chunks,
      received: this.db.receivedChunkIdx(task.id), // 已落盘分片 → 客户端据此跳过，实现断点续传
    };
  }
}

module.exports = { UploadService, HttpError, KIND_MIME };
