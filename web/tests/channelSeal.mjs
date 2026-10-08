// 仅测试用：模拟 Mac 设备端产出 SPEC §5 的「加密传输（通道口令）」外层信封，好让 e2e 能往
// 真服务端写入并被 GET /api/hosts 索引出来。
// 口径与 syncd/server/channel_passphrase.go 完全一致：口令经 PBKDF2-HMAC-SHA512（21 万轮、
// 16 字节随机盐、32 字节密钥）派生，AES-256-GCM，iv 为 12 字节随机数，ciphertext 是 WebCrypto
// 直接产出的 ct||tag，AAD 为空。用 WebCrypto 而不是 node:crypto，是为了让"浏览器里的实现"和
// 服务端、Swift 三方的字节口径互相对照。
// 这不是浏览器解密路径——src/ 里没有任何加解密代码，也不允许有（tests/gate.mjs 负责把守）。
import { strict as assert } from 'node:assert';
import { pbkdf2Sync, createHash, randomBytes } from 'node:crypto';

export const KDF_ALGORITHM = 'pbkdf2-sha512-cc';
export const ROUNDS = 210000;
export const SALT_BYTES = 16;
export const KEY_BYTES = 32;
export const MIN_PASSPHRASE_CHARS = 8;
// 指纹的域前缀与服务端/客户端逐字相同：同一句口令在三方算出同一个 6 位码。
export const FINGERPRINT_DOMAIN = 'yank-channel-v1|';

function b64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

/** 口令按"字数"下限把关（中文一个字算一个），Go 侧按 rune、Swift 侧按 Character。 */
export function channelPassphrase(text) {
  const clean = String(text).trim();
  assert.ok([...clean].length >= MIN_PASSPHRASE_CHARS, `通道口令至少 ${MIN_PASSPHRASE_CHARS} 个字`);
  return clean;
}

export function channelFingerprint(text) {
  const digest = createHash('sha256').update(FINGERPRINT_DOMAIN + channelPassphrase(text), 'utf8').digest();
  return digest.subarray(0, 3).toString('hex').toUpperCase();
}

function deriveKey(passphrase, salt) {
  return new Uint8Array(pbkdf2Sync(passphrase, salt, ROUNDS, KEY_BYTES, 'sha512'));
}

/** 产出可 JSON.stringify 的通道信封对象；manifestObject 是清单对象，明文按 UTF-8 JSON 上传。 */
export async function sealChannel(passphrase, manifestObject, { salt, iv } = {}) {
  const text = channelPassphrase(passphrase);
  const realSalt = Uint8Array.from(salt ?? randomBytes(SALT_BYTES));
  const realIv = Uint8Array.from(iv ?? randomBytes(12));
  assert.equal(realIv.length, 12, 'iv 必须是 12 字节');
  const imported = await crypto.subtle.importKey('raw', deriveKey(text, realSalt), 'AES-GCM', false, [
    'encrypt',
  ]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: realIv },
      imported,
      new TextEncoder().encode(JSON.stringify(manifestObject)),
    ),
  );
  return {
    formatVersion: 1,
    layer: 'channel',
    cipher: 'AES-256-GCM',
    kdf: {
      algorithm: KDF_ALGORITHM,
      salt: b64(realSalt),
      rounds: ROUNDS,
      keyLengthBytes: KEY_BYTES,
    },
    iv: b64(realIv),
    ciphertext: b64(sealed),
  };
}
