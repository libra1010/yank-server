// 仅测试用：按 SPEC §3 产出 v2 上传体 —— 主机/片段各一个数组，每行自己带一格端侧密文，
// 账本在顶层 `meta` 那一格里。派生与拼接口径与 Swift 侧 RowCipher 逐字节一致：
// 一次同步只派生一把端到端密钥（顶层 kdf 那一块），每一格各自换新 12 字节 nonce，
// 密文是 WebCrypto 直接产出的 ct‖tag，前面拼上 nonce。
// 这不是浏览器解密路径 —— src/ 里没有任何加解密代码，也不允许有（tests/gate.mjs 把守）。
import { pbkdf2Sync, randomBytes } from 'node:crypto';

export const E2E_ROUNDS = 1200000; // Swift PassphraseCipher.recordedDefaultRounds
export const E2E_CIPHER = 'aes-256-gcm';
export const FORMAT_VERSION = 2;

function isoSeconds(date) {
  return new Date(Math.floor(date.getTime() / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** 产出一包 v2 上传体（对象，可直接 JSON.stringify）。 */
export async function buildUploadV2({ syncPassphrase, rounds = E2E_ROUNDS, revision = 1,
  deviceID = 'node-test', hosts = [], snippets = [], createdAt = new Date(),
  aliases = {}, tombstones = [], secretAccountsPending = [] }) {
  const salt = randomBytes(16);
  const key = await crypto.subtle.importKey('raw',
    Uint8Array.from(pbkdf2Sync(syncPassphrase, salt, rounds, 32, 'sha512')),
    'AES-GCM', false, ['encrypt']);
  // 每一格：新随机 12 字节 nonce 拼在 WebCrypto 的 ct‖tag 前面，与 Swift 的 combined 同序。
  const sealCell = async (value) => {
    const nonce = randomBytes(12);
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key,
      new TextEncoder().encode(JSON.stringify(value))));
    const combined = new Uint8Array(12 + sealed.length);
    combined.set(nonce, 0);
    combined.set(sealed, 12);
    return Buffer.from(combined).toString('base64');
  };
  const hostRows = [];
  for (const host of hosts) {
    const { name, group, hostname, port, username, authKind, notes, jump, profile, secrets } = host;
    hostRows.push({ name, group, hostname, port, username, authKind,
      notes: notes ?? '', jump: jump ?? '',
      secret: await sealCell({ profile: profile ?? { name, hostname }, secrets: secrets ?? [] }) });
  }
  const snippetRows = [];
  for (const snippet of snippets) {
    const { name, group, body, params, updatedAt, id } = snippet;
    snippetRows.push({ name, group, body, params: params ?? '', updatedAt,
      secret: await sealCell({ id: id ?? name, body, updatedAt }) });
  }
  return { cipher: E2E_CIPHER, createdAt: isoSeconds(createdAt), formatVersion: FORMAT_VERSION,
    kdf: { algorithm: 'pbkdf2-sha512-cc', keyLengthBytes: 32, rounds, salt: b64(salt) },
    hosts: hostRows, meta: await sealCell({ revision, deviceID,
      updatedAt: isoSeconds(createdAt), aliases, tombstones, secretAccountsPending }),
    snippets: snippetRows };
}

function b64(bytes) {
  return Buffer.from(bytes).toString('base64');
}
