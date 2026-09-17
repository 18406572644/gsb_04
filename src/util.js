'use strict';

const crypto = require('node:crypto');

/** 生成随机 ID（用户 ID / 房间 ID / clientMsgId 兜底等） */
function randomId(prefix = '') {
  return prefix + crypto.randomBytes(9).toString('base64url'); // 12 字符
}

/** 生成随机 token 的随机部分 */
function randomSecret() {
  return crypto.randomBytes(24).toString('base64url');
}

/**
 * 演示级 token：`<userId>.<random>.<hmac>`，服务端用 HMAC 校验防伪造。
 * 生产环境应替换为 JWT/会话体系，但接口形状保持一致。
 */
function signToken(userId, random, secret) {
  const payload = `${userId}.${random}`;
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token, secret) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [userId, random, sig] = parts;
  const expect = crypto
    .createHmac('sha256', secret)
    .update(`${userId}.${random}`)
    .digest('base64url');
  // 恒定时间比较，防时序侧信道
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return userId;
}

/** 校验字符串字段：非空、长度上限 */
function isNonEmptyString(v, maxLen) {
  return typeof v === 'string' && v.length > 0 && v.length <= maxLen;
}

/** 安全整数且落在区间内 */
function isInt(v, min = -Infinity, max = Infinity) {
  return Number.isInteger(v) && v >= min && v <= max;
}

/** 合法的 64 位十六进制 sha256（小写） */
function isSha256(v) {
  return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
}

/** 清洗文件名：去目录部分、去控制字符，只保留纯展示/下载名 */
function safeFileName(name) {
  const base = String(name == null ? '' : name).split(/[\\/]/).pop();
  let out = '';
  for (const ch of base) {
    const c = ch.charCodeAt(0);
    if (c < 0x20 || c === 0x7f) continue;
    out += ch;
  }
  out = out.replace(/^\.+/, '').slice(0, 255);
  return out || 'file';
}

/** HMAC 签名通用原语 */
function hmacSign(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

/**
 * 下载票：`at.<userId>.<assetId>.<expMs>.<hmac>`。
 * 不与登录 token 互通；服务端恒定时间验签并检查过期。
 */
function signAssetTicket(userId, assetId, expMs, secret) {
  const payload = `${userId}.${assetId}.${expMs}`;
  return `at.${payload}.${hmacSign(secret, payload)}`;
}

function verifyAssetTicket(ticket, secret, nowMs = Date.now()) {
  if (typeof ticket !== 'string') return null;
  const parts = ticket.split('.');
  if (parts.length !== 5 || parts[0] !== 'at') return null;
  const [, userId, assetId, expStr, sig] = parts;
  const expMs = Number(expStr);
  if (!Number.isInteger(expMs) || nowMs > expMs) return null;
  const expect = hmacSign(secret, `${userId}.${assetId}.${expMs}`);
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return { userId, assetId, expMs };
}

/** 解析 JSON 文本帧，失败返回 null */
function parseFrame(raw) {
  if (typeof raw !== 'string' && !Buffer.isBuffer(raw)) return null;
  const text = raw.toString();
  if (text.length > 64 * 1024) return null; // 帧大小硬上限，防内存攻击
  try {
    const obj = JSON.parse(text);
    return obj && typeof obj === 'object' && typeof obj.type === 'string' ? obj : null;
  } catch {
    return null;
  }
}

const now = () => Date.now();

module.exports = {
  randomId, randomSecret, signToken, verifyToken,
  isNonEmptyString, isInt, isSha256, safeFileName,
  signAssetTicket, verifyAssetTicket,
  parseFrame, now,
};
