// 真机端到端：打真 Go 服务（默认 127.0.0.1:8899，BASE= 可覆盖）。
// 流程：注册 → 登录 → 配对码 → 换设备令牌 → 以「加密传输」通道信封写入两版清单 →
// GET /api/hosts 看服务端索引出的元数据 → 历史 → POST /api/blob/rollback 用会话令牌回退 →
// 吊销设备。口令/私钥本体从头到尾不在响应里；本脚本用 canary 证明它们连服务端答复都没混进。
// 注意：PUT /api/blob 在这里只是**模拟 Mac 设备端**（设备令牌）；管理端自身从不这么调（gate.mjs 把守）。
import { strict as assert } from 'node:assert';
import { sealChannel } from './channelSeal.mjs';
import { buildUploadV2 } from './uploadV2.mjs';

const BASE = process.env.BASE ?? 'http://127.0.0.1:8899';
const USER = process.env.DT_USER ?? 'console-e2e';
const LOGIN_PW = process.env.DT_PW ?? 'console-login-pw-10';
// 仅本机测试用的通道口令（自己定的一句，至少 8 个字）；起服务时要在页面上配同一个值。
const CHANNEL_KEY = process.env.DT_CHANNEL_KEY ?? 'yank-通道口令-端到端回归';
// 凭据 canary：出现在设备写的清单里，但绝不允许出现在服务端任何一个答复里。
const FAKE_PASSWORD = 'e2e-绝不出屏的SSH口令';
const FAKE_VAULT = Buffer.from('e2e-假私钥字节').toString('base64');

const log = (...a) => console.log(...a);

async function api(path, { method = 'GET', token, body, ifMatch } = {}) {
  const h = new Headers();
  if (body !== undefined) h.set('content-type', 'application/json');
  if (token) h.set('authorization', `Bearer ${token}`);
  if (ifMatch !== undefined) h.set('if-match', String(ifMatch));
  const res = await fetch(BASE + path, { method, headers: h, body: body && JSON.stringify(body) });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* 204 之类没有 body */
  }
  return { status: res.status, json, text, etag: res.headers.get('etag') };
}

function profile(i, name, group, hostname, port, username) {
  return {
    id: `00000000-0000-4000-8000-00000000000${i + 1}`,
    name,
    group,
    hostname,
    port,
    username,
    // 白名单外的字段：服务端只索引那 8 个明文键，凭据与 id 留在行内那一格密文里。
    auth: { kind: 'password', password: FAKE_PASSWORD },
  };
}

// 端到端同步口令：v2 每一行的 secret 与顶层 meta 都由它派生的密钥封（SPEC §3）。
const SYNC_PASS = 'node-e2e-端到端口令-至少八字';

/** v2 上传体：明文只有那 8 个键，profile 本体（含 id 与凭据）在行内密文格里。 */
function uploadBody(revision, profiles) {
  return buildUploadV2({
    syncPassphrase: SYNC_PASS, revision, deviceID: 'node-e2e-verifier',
    hosts: profiles.map((f) => ({ name: f.name, group: f.group, hostname: f.hostname,
                                  port: f.port, username: f.username, authKind: 'password',
                                  notes: '', jump: '', profile: f,
                                  secrets: [{ account: `ssh:${f.name}:${f.username}`,
                                              kind: 'password', data: FAKE_PASSWORD }] })),
  });
}

// v1 那套「整包 manifest + secretVault」的形状已经退役（SPEC §3）：现在每行自己带一格密文。
// FAKE_VAULT 留着当第二条 canary —— 它现在被塞进行内密文格里，同样不许从服务端漏出来。

log(`── 目标服务 ${BASE} ──`);
const health = await api('/api/healthz');
assert.equal(health.status, 200);
log('healthz:', health.json);

// 账号可能已存在（重复跑），409 直接当成功。
const reg = await api('/api/register', { method: 'POST', body: { user: USER, password: LOGIN_PW } });
log('register:', reg.status, reg.json?.user ?? reg.json?.reason ?? reg.json);

const loginRes = await api('/api/login', { method: 'POST', body: { user: USER, password: LOGIN_PW } });
assert.equal(loginRes.status, 200, `登录失败：${JSON.stringify(loginRes.json)}`);
const session = loginRes.json.token;
log('login ok, userId:', loginRes.json.userId);

const pair = await api('/api/pair', { method: 'POST', token: session });
assert.equal(pair.status, 200);
log('pair code:', pair.json.code, '|', pair.json.note);

const exchange = await api('/api/pair/exchange', {
  method: 'POST',
  body: { code: pair.json.code, deviceName: 'Node 验证设备' },
});
assert.equal(exchange.status, 200, JSON.stringify(exchange.json));
const deviceToken = exchange.json.deviceToken;
log('device token issued, deviceId:', exchange.json.deviceId);

// 通道口令只能在管理页这一路配（启动参数 -channel-key 已经删掉了），所以这里自己走同一条
// API 把它配下去：这个脚本从此不依赖服务端是怎么被启动的。
// 顺带把「只进不出」钉住：状态里只有存在性与 6 位指纹，清单接口在未启用时也是 200（空表）。
const stateProbe = await api('/api/channel', { token: session });
assert.equal(stateProbe.status, 200, `GET /api/channel 应可读：${stateProbe.status} ${stateProbe.text}`);
const channelSet = await api('/api/channel', { method: 'POST', token: session, body: { key: CHANNEL_KEY } });
assert.equal(channelSet.status, 200, `页面配置通道口令失败：${channelSet.status} ${channelSet.text}`);
assert.ok(!channelSet.text.includes(CHANNEL_KEY), '应答里不许回显口令');
const channelOn = channelSet.json.enabled && channelSet.json.source === 'page';
assert.ok(channelOn, `配置之后应报告 page/已启用，实际 ${channelSet.text}`);
log('通道口令已配 → 指纹', channelSet.json.fingerprint);

// ── 设备端写两版通道信封（模拟 Mac，设备令牌；管理端自己从不走这条路）──
const env1 = await sealChannel(CHANNEL_KEY, await uploadBody(1, [
  profile(0, '生产 Web-01', '生产', '10.0.0.1', 22, 'root'),
  profile(1, '默认 Dev-02', '默认', '10.0.0.2', 2222, 'devops'),
]));
const put1 = await api('/api/blob', { method: 'PUT', token: deviceToken, body: env1, ifMatch: 0 });
assert.equal(put1.status, 200, JSON.stringify(put1.json));
log('设备写入第 1 版 → revision', put1.json.revision);

const env2 = await sealChannel(CHANNEL_KEY, await uploadBody(2, [
  profile(0, '备份 Box-03', '备份', '10.0.0.3', 22, 'backup'),
]));
const put2 = await api('/api/blob', { method: 'PUT', token: deviceToken, body: env2, ifMatch: put1.json.revision });
assert.equal(put2.status, 200, JSON.stringify(put2.json));
log('设备写入第 2 版 → revision', put2.json.revision);

const stale = await api('/api/blob', { method: 'PUT', token: deviceToken, body: env1, ifMatch: 1 });
assert.equal(stale.status, 409);
log('旧版本号写入被拒（409）:', stale.json.reason);

// ── GET /api/hosts：管理端清单的唯一来源 ──
if (channelOn) {
  const hosts = await api('/api/hosts', { token: session });
  assert.equal(hosts.status, 200);
  assert.ok(Array.isArray(hosts.json), '响应必须是裸 JSON 数组');
  log('GET /api/hosts →', hosts.json.map((r) => `${r.name}(${r.group} ${r.hostname}:${r.port} ${r.username} #${r.revision})`).join(' , '));
  // ReplaceHosts 整表替换：当前清单应只剩第 2 版里的那台。
  assert.deepEqual(hosts.json.map((r) => r.name), ['备份 Box-03']);
  const row = hosts.json[0];
  // §5.1 那份白名单八个字段 + 服务端盖的来源版本号，多一个都不许有（凭据字段名一律不在）。
  assert.deepEqual(Object.keys(row).sort(),
    ['authKind', 'group', 'hostname', 'jump', 'name', 'notes', 'port', 'revision', 'username'],
    '每行只应有白名单八个字段加来源版本号');
  // 最关键的一条：凭据 canary 连服务端答复的原文里都不存在。
  assert.ok(!hosts.text.includes(FAKE_PASSWORD), '泄漏：GET /api/hosts 回显了 SSH 口令');
  assert.ok(!hosts.text.includes(FAKE_VAULT), '泄漏：GET /api/hosts 回显了凭据库');
  assert.ok(!hosts.text.includes('secretMaterial') && !hosts.text.includes('secretVault'),
    '泄漏：清单里出现了凭据字段名');
  assert.ok(!hosts.text.includes(FAKE_VAULT), '泄漏：GET /api/hosts 回显了行内密文格的内容');

  const anon = await api('/api/hosts');
  assert.equal(anon.status, 401, `匿名访问应 401，实际 ${anon.status}`);
  log('匿名 GET /api/hosts →', anon.status, anon.json.reason);
}

// ── 历史元数据 ──
const history = await api('/api/blob/history', { token: session });
assert.equal(history.status, 200);
assert.ok(history.json.items.length >= 2, '至少两条历史');
log('历史:', history.json.items.map((h) => `#${h.revision} ${h.bytes}B`).join(' , '));

// ── 回退：管理端会话令牌走 POST /api/blob/rollback ──
const rb = await api('/api/blob/rollback', { method: 'POST', token: session, body: { revision: 1 } });
assert.equal(rb.status, 200, JSON.stringify(rb.json));
assert.ok(typeof rb.json.revision === 'number' && rb.json.revision > 2);
log(`会话令牌回退到第 1 版 → 服务端现在是第 ${rb.json.revision} 版`);

// 回退后版本号确实前滚了（GET /api/blob 的 ETag）。
const after = await api('/api/blob', { token: session });
assert.equal(after.status, 200);
assert.equal(Number(after.etag), rb.json.revision, 'ETag 应与回退返回的新版本号一致');
log('GET /api/blob ETag =', after.etag);

if (channelOn) {
  // 只记录、不断言：回退路径当前是否同步重建 hosts 索引属于服务端口径（见 README 备忘）。
  const hostsAfter = await api('/api/hosts', { token: session });
  log('回退后 GET /api/hosts →', hostsAfter.json.map((r) => `${r.name} #${r.revision}`).join(' , '));
}

// 设备令牌没有用户会话权限，回退必须拒（401）；匿名同理。
const rbDevice = await api('/api/blob/rollback', { method: 'POST', token: deviceToken, body: { revision: 1 } });
assert.equal(rbDevice.status, 401);
log('设备令牌调回退 →', rbDevice.status, rbDevice.json?.reason);
const rbAnon = await api('/api/blob/rollback', { method: 'POST', body: { revision: 1 } });
assert.equal(rbAnon.status, 401);

// 不存在的版本 → 404，中文理由可转达。
const rbMissing = await api('/api/blob/rollback', { method: 'POST', token: session, body: { revision: 999 } });
assert.equal(rbMissing.status, 404);
log('回退到不存在的版本 →', rbMissing.status, rbMissing.json?.reason);

// ── 设备列表与吊销 ──
const devices = await api('/api/devices', { token: session });
assert.equal(devices.status, 200);
log('设备:', devices.json.items.map((d) => `${d.name}/${d.id}/revoked=${d.revoked}`).join(' , '));

const revoked = await api('/api/devices/revoke', { method: 'POST', token: session, body: { deviceId: exchange.json.deviceId } });
log('吊销设备:', revoked.status);
const afterRevoke = await api('/api/blob', { method: 'PUT', token: deviceToken, body: env2, ifMatch: Number(after.etag) });
assert.equal(afterRevoke.status, 401);
log('被吊销设备再写入 →', afterRevoke.status, afterRevoke.json.reason);

await api('/api/logout', { method: 'POST', token: session });
log('── 端到端全部通过 ──');
