// 真机端到端（页面配置通道口令）：打一个**什么都没配**就启动的真 Go 服务（启动参数那一路已经
// 删掉了，口令只能在这个页面配），走完「口令只进不出」的全部状态迁移，全程只用 HTTP，
// 不碰 Go 测试里那些内部构造：
//
//   无口令 → 通道信封照旧存成密文；/api/hosts 仍是 200，只是这一条链路没给出清单（空数组）
//   本页保存正确口令 → 存量信封当场被解开并入索引（不用重推、不用重启）
//   本页保存写错的口令 → 指纹变了，既有索引一行不少
//   清除 → /api/hosts 依然 200：已入库的是明文字段，不跟着口令一起消失
//
// 反例一并把守：太短的口令 400；应答里绝不回显口令；设备令牌既读不到也改不了这把口令。
// 指纹这一-项是三方对照：node 这里独立算出来的值必须与服务端报的一致（另两方见 Go 测试与
// Swift 门禁 Checks_SyncChannel.swift）。
// 跑法：BASE=http://127.0.0.1:PORT node tests/channelKeyPage.mjs
import assert from 'node:assert/strict';
import { channelFingerprint, sealChannel } from './channelSeal.mjs';
import { buildUploadV2 } from './uploadV2.mjs';

const BASE = process.env.BASE ?? 'http://127.0.0.1:8899';
// 两端各填同一句话：不再是 64 个字符的十六进制，是自己定的一句口令。
const PASS = process.env.DT_CHANNEL_KEY ?? 'yank-通道口令-页面配置验证';
// 另一句合法但不同的口令：专门用来演「写错了也不该毁掉清单」。
const WRONG_PASS = process.env.DT_CHANNEL_KEY_WRONG ?? 'yank-通道口令-这一句是填错的';
const USER = process.env.DT_PAGE_USER ?? `gate-channel-page.${Date.now()}`;
const LOGIN_PASS = 'a-long-enough-login-pass';

const log = (...a) => console.log(...a);

async function api(path, { method = 'GET', token, body, raw, ifMatch } = {}) {
  const h = new Headers();
  if (token) h.set('authorization', `Bearer ${token}`);
  if (body || raw) h.set('content-type', 'application/json');
  // 设备端的写入协议：If-Match 带期望版本号，服务端靠它做乐观并发。
  if (ifMatch !== undefined) h.set('if-match', String(ifMatch));
  const res = await fetch(BASE + path, {
    method,
    headers: h,
    body: body ? JSON.stringify(body) : raw,
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* 空响应或非 JSON，交给调用方判断 */
  }
  return { status: res.status, json, text };
}

log(`── 目标服务 ${BASE}（应没有任何通道口令可继承）──`);

assert.equal((await api('/api/healthz')).status, 200, '同步服务没起来');
await api('/api/register', { method: 'POST', body: { user: USER, password: LOGIN_PASS } });
const login = await api('/api/login', { method: 'POST', body: { user: USER, password: LOGIN_PASS } });
assert.equal(login.status, 200, `登录失败：${login.text}`);
const token = login.json.token;

const pair = await api('/api/pair', { method: 'POST', token });
assert.equal(pair.status, 200, `配对码申请失败：${pair.text}`);
const exchange = await api('/api/pair/exchange', {
  method: 'POST',
  body: { code: pair.json.code, deviceName: 'gate-page' },
});
assert.equal(exchange.status, 200, `换取设备令牌失败：${exchange.text}`);
const device = exchange.json.deviceToken;

// 版本号自己跟着成功写入走：模拟设备端拿到 ETag 后下一次带上新值。
let revision = 0;
async function pushEnvelope(raw) {
  const res = await api('/api/blob', { method: 'PUT', token: device, raw, ifMatch: revision });
  if (res.status === 200) revision = Number(res.json.revision);
  return res;
}

// v2 上传体（SPEC §3）：一行主机一格端侧密文，账本在顶层 meta 那一格里。服务端读的就是那
// 8 个明文键；profileID 与钥匙串账号名在密文格里，它连读都读不到。
const SYNC_PASS = 'node-端到端口令-至少八个字';
const uploadBody = await buildUploadV2({
  syncPassphrase: SYNC_PASS, revision: 1, deviceID: 'gate-page',
  hosts: [{ name: '页面配置验证机', group: '门禁', hostname: 'page.example.com', port: 2200,
            username: 'ops', authKind: 'password',
            profile: { id: 'P', name: '页面配置验证机',
                       auth: { password: { secretAccount: 'ssh:page-verify:ops' } } } }],
});
// 通道层的明文就是这一整包 —— 外面不再挂任何明文数组（那正是用户拍板要改掉的东西）。
const envelope = JSON.stringify(await sealChannel(PASS, uploadBody));
const outerKeys = Object.keys(JSON.parse(envelope)).sort().join(',');
assert.equal(outerKeys, 'cipher,ciphertext,formatVersion,iv,kdf,layer',
  `通道外层只许这 6 个键，清单必须在密文里面：实际 ${outerKeys}`);
// 派生三件套必须随信封走，否则服务端无从重算：这一条把 §5 的形状钉在这里（Go/Swift 各钉一遍）。
const kdf = JSON.parse(envelope).kdf;
assert.deepEqual(Object.keys(kdf).sort(), ['algorithm', 'keyLengthBytes', 'rounds', 'salt'].sort(),
  `kdf 块应是口令派生的那四个参数，实际 ${JSON.stringify(kdf)}`);
assert.equal(kdf.algorithm, 'pbkdf2-sha512-cc', '算法名要与 Go/Swift 两侧逐字一致');
assert.equal(kdf.rounds, 210000, '轮数是写死的常量，不是信封说了算');
assert.equal(kdf.keyLengthBytes, 32, '派生出来的是 32 字节密钥');
assert.equal(Buffer.from(kdf.salt, 'base64').length, 16, 'salt 应是 16 字节');
// 两次封装必须换 salt 也换 iv：同一份清单两次上传的字节不该相同。
const again = JSON.parse(JSON.stringify(await sealChannel(PASS, uploadBody)));
assert.ok(again.kdf.salt !== kdf.salt && again.iv !== JSON.parse(envelope).iv,
  'salt/iv 没用新随机数');

// ① 无口令：通道信封照旧当密文收下；清单接口不靠口令才开门，而这一包的数组全在解不开的
//    密文里面，所以是"能读，但这一台还没上报过清单"。
const putFirst = await pushEnvelope(envelope);
assert.equal(putFirst.status, 200, `无口令时通道信封应存为密文，实际 ${putFirst.status} ${putFirst.text}`);
const hostsOff = await api('/api/hosts', { token });
assert.equal(hostsOff.status, 200, `未启用通道加密时 /api/hosts 也该 200（用户拍板），实际 ${hostsOff.status}`);
assert.deepEqual(hostsOff.json, [], '清单锁在服务端解不开的通道密文里时，清单应当是空的');
const stateOff = await api('/api/channel', { token });
assert.equal(stateOff.status, 200, `GET /api/channel 应可读，实际 ${stateOff.status} ${stateOff.text}`);
assert.deepEqual(
  stateOff.json,
  { enabled: false, source: 'none', fingerprint: '' },
  '初始状态应是未启用、无指纹',
);

// ② 太短的口令一律 400，且错误信息指向通道密钥；库里那一行一个字节都不动。
for (const bad of ['abcd', '七个字的中', '   123   ', 'a'.repeat(7)]) {
  const res = await api('/api/channel', { method: 'POST', token, body: { key: bad } });
  assert.equal(res.status, 400, `口令 ${JSON.stringify(bad)} 应 400，实际 ${res.status} ${res.text}`);
  assert.match(res.json.reason, /通道密钥/, `拒绝理由应指向通道密钥：${res.text}`);
}
assert.deepEqual((await api('/api/channel', { token })).json,
  { enabled: false, source: 'none', fingerprint: '' }, '被拒的口令不该改动状态');

// ③ 保存正确口令：存量信封当场建立索引，不用重推、不用重启。
const saved = await api('/api/channel', { method: 'POST', token, body: { key: PASS } });
assert.equal(saved.status, 200, `页面配置口令失败：${saved.status} ${saved.text}`);
assert.deepEqual(
  saved.json,
  { enabled: true, source: 'page', fingerprint: channelFingerprint(PASS) },
  `应报告 page 来源与正确指纹（node 独立算的那一个），实际 ${saved.text}`,
);
assert.ok(!saved.text.includes(PASS), '响应绝不回显口令');

const hostsOn = await api('/api/hosts', { token });
assert.equal(hostsOn.status, 200, `配置口令后 /api/hosts 应可用，实际 ${hostsOn.status} ${hostsOn.text}`);
assert.equal(hostsOn.json.length, 1, `存量信封应就地索引出 1 行，实际 ${hostsOn.text}`);
assert.equal(hostsOn.json[0].hostname, 'page.example.com', '索引内容应是那台验证机');
assert.equal(hostsOn.json[0].username, 'ops', '登录用户要在白名单字段里');
assert.equal(hostsOn.json[0].authKind, 'password',
  `认证方式要能看出来（用户拍板的这一列），实际 ${hostsOn.text}`);
assert.ok(!hostsOn.text.includes('ssh:page-verify:ops'),
  '钥匙串账号名不许跟着判别名一起漏给浏览器');

// ④ 写错口令：指纹跟着变，但既有索引一行都不能掉。
const mistyped = await api('/api/channel', { method: 'POST', token, body: { key: WRONG_PASS } });
assert.equal(mistyped.status, 200, `配置另一句合法口令不该失败：${mistyped.text}`);
assert.equal(mistyped.json.fingerprint, channelFingerprint(WRONG_PASS), '指纹应随页面口令变化');
assert.ok(!mistyped.text.includes(WRONG_PASS), '换口令的响应也不回显口令');
const hostsAfterTypo = await api('/api/hosts', { token });
assert.equal(hostsAfterTypo.status, 200, '写错的口令不该让清单接口出错');
assert.equal(hostsAfterTypo.json.length, 1, `打不开存量信封也不该清空索引，实际 ${hostsAfterTypo.text}`);
// 此时推送用正确口令封的信封必须被拒——服务端认的是本页这一句。
const rejected = await pushEnvelope(envelope);
assert.equal(rejected.status, 400, `口令不符的推送必须被拒，实际 ${rejected.status} ${rejected.text}`);

// ⑤ 改回来：立刻能用，同样不需要重推。
const restored = await api('/api/channel', { method: 'POST', token, body: { key: PASS } });
assert.equal(restored.json.fingerprint, channelFingerprint(PASS), '指纹应恢复');
const accepted = await pushEnvelope(envelope);
assert.equal(accepted.status, 200, `改回正确口令后推送应放行，实际 ${accepted.status} ${accepted.text}`);

// ⑥ 清除：回到未启用；本页配置没了，设备令牌也无权碰这把口令。
const cleared = await api('/api/channel', { method: 'POST', token, body: { key: '' } });
assert.equal(cleared.status, 200, `清除失败：${cleared.status} ${cleared.text}`);
assert.equal(cleared.json.source, 'none', `清除后应回到 none，实际 ${cleared.text}`);
assert.equal(cleared.json.enabled, false, '清除后不该声称已启用');
const hostsCleared = await api('/api/hosts', { token });
assert.equal(hostsCleared.status, 200, '清除口令后清单接口也该照常 200');
assert.equal(hostsCleared.json.length, 1,
  `已入库的是明文字段，清除口令不该把清单一起抹掉，实际 ${hostsCleared.text}`);

// ⑦ 用户拍板的那一条：通道口令处于「未启用」时，v2 那一包明文上传体必须入库、必须能列。
const stillOff = await api('/api/channel', { token });
assert.equal(stillOff.json.enabled, false, '这一步的前提就是口令没启用');
const clearBody = await buildUploadV2({
  syncPassphrase: SYNC_PASS, revision: 9, deviceID: 'gate-page',
  hosts: [{ name: '明文验证机', group: '默认', hostname: 'clear.example.com', port: 22,
            username: 'ubuntu', authKind: 'private-key', notes: '不需要通道口令',
            jump: 'ops@10.0.0.9:22' }],
});
const cleartextPush = JSON.stringify(clearBody);
assert.equal((await pushEnvelope(cleartextPush)).status, 200, '未启用口令时明文上传体该被收下');
const clearHosts = await api('/api/hosts', { token });
assert.equal(clearHosts.status, 200, `未启用口令时清单接口该 200，实际 ${clearHosts.status}`);
assert.equal(clearHosts.json.length, 1, `新那一版该整批覆盖旧索引，实际 ${clearHosts.text}`);
const row = clearHosts.json[0];
assert.deepEqual(
  { name: row.name, group: row.group, hostname: row.hostname, port: row.port,
    username: row.username, authKind: row.authKind, notes: row.notes, jump: row.jump },
  { name: '明文验证机', group: '默认', hostname: 'clear.example.com', port: 22, username: 'ubuntu',
    authKind: 'private-key', notes: '不需要通道口令', jump: 'ops@10.0.0.9:22' },
  `八个字段要一个不少地回到界面上：${clearHosts.text}`);
assert.ok(!clearHosts.text.includes('ssh:page-verify:ops'), '行内密文格的内容不许出现在接口里');
assert.ok(Number(row.revision) > 0, `来源版本号要在：${clearHosts.text}`);

assert.equal((await api('/api/channel', { token: device })).status, 401, '设备令牌读通道状态应 401');
const byDevicePut = await api('/api/channel', { method: 'POST', token: device, body: { key: PASS } });
assert.equal(byDevicePut.status, 401, `设备令牌配置服务端口令应 401，实际 ${byDevicePut.status}`);
assert.equal((await api('/api/channel')).status, 401, '匿名读通道状态应 401');

log('  ✓ 通道口令的页面配置：状态迁移、索引重建、反例全部对得上');
