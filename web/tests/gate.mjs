// 负向门禁：证明「浏览器端解密端到端口令」这条能力已经被连根拔掉。
// 扫描范围 = src/ 全部源码 + npm run build 之后的 dist/ 产物（先 build 再跑本脚本）。
// 断言分四组：
//   A 浏览器里不存在口令解密路径（deriveKey / PBKDF2 / AES-GCM / passphrase / secret 字段名）
//   B 页面上不存在"收集端到端口令"的输入控件；遮罩位只允许登录 1 + 改登录口令 3 + 通道密钥 1
//   C 令牌不进 console / URL（会话落 localStorage 是拍板过的行为，见 sessionStore.ts）
//   D 管理端不再碰写入类旧路径（PUT /api/blob、If-Match、信封正文）
// 跑法：node tests/gate.mjs
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = path.join(ROOT, 'src');
const DIST = path.join(ROOT, 'dist');

function walk(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

function textFiles(dir, filter) {
  return walk(dir).filter((f) => filter(f)).map((f) => ({ file: f, text: readFileSync(f, 'utf8') }));
}

const rel = (f) => path.relative(ROOT, f);

if (!existsSync(DIST)) {
  console.error('dist/ 不存在：先跑 npm run build，再跑本门禁。');
  process.exit(1);
}

const srcFiles = textFiles(SRC, () => true);
const distFiles = textFiles(DIST, (f) => /\.(js|css|html)$/.test(f));
const joined = (list) => list.map((f) => f.text).join('\n');

// ── A. 口令解密路径必须整个消失 ────────────────────────────────────────────
const FORBIDDEN = [
  'deriveKey',
  'PBKDF2',
  'pbkdf2',
  'AES-GCM',
  'aes-256-gcm',
  'passphrase',
  'Passphrase',
  'secretMaterial',
  'secretVault',
];
for (const needle of FORBIDDEN) {
  for (const { file, text } of srcFiles) {
    assert.ok(!text.includes(needle), `A 泄漏：src/ 里仍出现「${needle}」→ ${rel(file)}`);
  }
  for (const { file, text } of distFiles) {
    assert.ok(!text.includes(needle), `A 泄漏：构建产物里仍出现「${needle}」→ ${rel(file)}`);
  }
}
console.log(`A 通过：src/（${srcFiles.length} 个文件）与 dist/（${distFiles.length} 个文件）里都没有 ` +
  FORBIDDEN.map((n) => `"${n}"`).join(' / '));

// ── B. 不允许存在口令输入控件 ─────────────────────────────────────────────
// src：每个 <label>…<input…>…</label> 控件块里不得出现「口令」；
// 全 src 只允许一个 type="password"，且它属于登录页、标签必须是「管理端密码」。
const vueFiles = srcFiles.filter((f) => f.file.endsWith('.vue'));
const labelBlocks = [];
for (const { file, text } of vueFiles) {
  const re = /<label[^>]*>[\s\S]*?<\/label>/g;
  for (const block of text.match(re) ?? []) {
    if (block.includes('<input')) labelBlocks.push({ file, block });
  }
}
// 真正要禁的是"这一页在收集端到端口令"：标签里出现 同步口令/端到端 就是违规。
// 「原口令/新口令」（改管理端登录口令）与「通道密钥」都是本页自己的凭据，不是端到端那把。
const END_TO_END = ['同步口令', '端到端口令', '端到端密钥'];
for (const { file, block } of labelBlocks) {
  for (const needle of END_TO_END) {
    assert.ok(!block.includes(needle), `B 违规：输入控件在收集「${needle}」→ ${rel(file)}`);
  }
}
// 遮罩位只许出现在这三个文件里：登录（管理端密码）、改登录口令、通道密钥。
const PW_ALLOWED = { 'LoginView.vue': 1, 'PasswordCard.vue': 3, 'ChannelKeyCard.vue': 1 };
for (const { file, text } of vueFiles) {
  const n = (text.match(/type="password"/g) ?? []).length;
  const base = path.basename(file);
  assert.equal(n, PW_ALLOWED[base] ?? 0, `B 违规：${base} 的遮罩输入框数量不对（${n}）`);
}
const pwCount = vueFiles.reduce((n, { text }) => n + (text.match(/type="password"/g) ?? []).length, 0);
assert.equal(pwCount, 5, `B 违规：src 里 type="password" 应恰好 5 处（登录 1 + 改登录口令 3 + 通道密钥 1），实际 ${pwCount}`);
const loginView = vueFiles.find(({ file }) => file.endsWith('LoginView.vue'));
assert.ok(loginView && /type="password"/.test(loginView.text),
  'B 违规：唯一的管理端登录密码框必须留在 LoginView.vue');
// dist：编译后的 input vnode 属性里 "password" 的处数必须与 src 一一对上（5 处），
// 且解密时代的名词一个都不许进产物。
const distJs = joined(distFiles.filter((f) => f.file.endsWith('.js')));
const distPw = (distJs.match(/type\s*:\s*"password"/g) ?? []).length;
assert.equal(distPw, pwCount, `B 违规：构建产物里 type:"password" 应与 src 的 ${pwCount} 处一致，实际 ${distPw}`);
for (const phrase of ['在本地解密', '本地解密']) {
  assert.ok(!joined([...srcFiles, ...distFiles]).includes(phrase),
    `B 违规：界面里仍残留「${phrase}」字样`);
}
// 通道密钥那一栏从今往后是**遮罩式**输入框：它不再是一串粘进来的 64 位十六进制，而是一句人自己
// 定的短密码（用户 2026-10-06 拍板），明文回显等于旁人瞥一眼就能用。所以这里反过来钉：
// 通道卡片必须是 type="password"，谁改回明文框就红给他看。管理端登录那一栏也仍是遮罩。
const cardVue = vueFiles.find(({ file }) => file.endsWith('ChannelKeyCard.vue'));
assert.ok(cardVue && /type="password"/.test(cardVue.text) && !/type="text"/.test(cardVue.text),
  'B 违规：通道密钥输入框必须是遮罩式 type="password"');
console.log(`B 通过：${labelBlocks.length} 个输入控件的标签没有一处声称在收集端到端口令；` +
  `type="password" 在 src 恰好 ${pwCount} 处（登录 1 + 改登录口令 3 + 通道密钥 1）、dist 与之一一对上；解密入口文案已清除`);

// ── C. 令牌/秘密卫生（延伸到新接口）──────────────────────────────────────
const srcText = joined(srcFiles);
// 会话令牌确实会落 localStorage（"刷新不掉登录"是拍板过的行为，见 src/sessionStore.ts 与
// tests/session*.mjs：先探测可用性、私密模式自动退回内存），所以这里禁的不再是"存储"本身，
// 而是把秘密摊到日志与 URL 上。
for (const needle of ['console.', 'debugger']) {
  assert.ok(!srcText.includes(needle),
    `C 违规：src 不允许出现「${needle}」（日志不留痕）`);
}
const bearer = (srcText.match(/Bearer/g) ?? []).length;
const bearerToken = (srcText.match(/Bearer \$\{token\.value\}/g) ?? []).length;
assert.ok(bearer > 0 && bearer === bearerToken,
  `C 违规：authorization 头只允许 "Bearer \${token.value}" 一种写法（${bearerToken}/${bearer}）`);
assert.ok(!/[?&](token|key|pass)=/.test(srcText), 'C 违规：令牌或密钥出现在 URL 查询里');
assert.doesNotMatch(srcText, /[`'"]\/api[^'"`]*\$\{/, 'C 违规：请求路径里拼进了变量（可能把令牌带进 URL）');
const tokenFiles = srcFiles.filter(({ text }) => /\btoken\b/.test(text)).map(({ file }) => rel(file)).sort();
assert.deepEqual(tokenFiles, ['src/sessionStore.ts', 'src/useApi.ts'],
  `C 违规：token 只允许活在 useApi.ts 与 sessionStore.ts（实际还出现在：${tokenFiles.join(', ') || '无'}）`);
const apiCallers = srcFiles.filter(({ text }) => text.includes('fetch('));
assert.deepEqual(apiCallers.map(({ file }) => rel(file)), ['src/useApi.ts'],
  'C 违规：网络请求必须集中在 useApi.ts');
for (const endpoint of ['/api/hosts', '/api/blob/rollback', '/api/channel']) {
  // 只算「被当作路径字面量传给 call/fetch」的调用点；注释与 UI 文案里提到接口名是允许的。
  const re = new RegExp(`(?:call|fetch)\\s*(?:<[^>]*>)?\\(\\s*['\`]${endpoint.replace('/', '\\/')}`, 'g');
  const users = srcFiles.filter(({ text }) => re.test(text)).map(({ file }) => rel(file));
  assert.deepEqual(users, ['src/useApi.ts'], `C 违规：${endpoint} 只允许在 useApi.ts 里被调用`);
}
// 通道密钥只进不出：接口契约里不许出现「把密钥带回来」的字段，本页也不许把密钥留在输入框里。
// 这两条是留给未来的红线——谁哪天觉得「回显一下密钥方便核对」，门禁就会红给他看。
const typesText = srcFiles.find(({ file }) => file.endsWith('types.ts'))?.text ?? '';
const channelIface = typesText.match(/interface ChannelState\s*\{[\s\S]*?\n\}/)?.[0] ?? '';
assert.ok(channelIface, 'C 违规：types.ts 里找不到 ChannelState 契约');
assert.doesNotMatch(channelIface, /\bkey\b/, 'C 违规：ChannelState 不得含密钥字段（服务端永不回传）');
const cardText = srcFiles.find(({ file }) => file.endsWith('ChannelKeyCard.vue'))?.text ?? '';
assert.match(cardText, /await setChannelKey\([\s\S]{0,400}draft\.value = ''/,
  'C 违规：保存/清除之后必须清空密钥输入框，页面上不留副本');
assert.doesNotMatch(cardText, /v-model="state/, 'C 违规：读回来的通道状态不得绑进输入控件');
console.log(
  'C 通过：无 storage/console 泄漏；Bearer 写法统一；/api/hosts、/api/blob/rollback、/api/channel 只在 useApi.ts',
);

// ── D. 旧写入路径彻底断开 ────────────────────────────────────────────────
assert.ok(!srcText.includes("method: 'PUT'"), 'D 违规：控制台仍在用 PUT /api/blob');
assert.ok(!srcText.includes('if-match'), 'D 违规：控制台仍在拼 If-Match（那是设备令牌的写入协议）');
assert.ok(!srcText.includes('/api/blob/at/'), 'D 违规：控制台不应再拉取信封正文');
assert.doesNotMatch(distJs, /method\s*:\s*['"]PUT['"]/, 'D 违规：产物里不应残留 PUT 调用');
console.log('D 通过：PUT /api/blob / If-Match / 信封正文拉取均已断开，回退只走 POST /api/blob/rollback');

console.log('负向门禁全部通过：浏览器看不到、也解不开端到端口令与密钥。');
