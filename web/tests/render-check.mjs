// DOM 泄漏与渲染冒烟：用 vite 的 SSR 通道把真组件渲染成 HTML，断言
//   (1) 主机元数据（GET /api/hosts 的形状）与代码片段（GET /api/snippets 的形状）能渲染；
//       片段隐去正文的中文提示逐字进正文列、{host} {user} 花括号进参数列；
//   (2) 口令、凭据材料字节、凭据库密文这些 canary 即使混进数据对象也绝不进 DOM；
//   (3) 界面上不存在端到端口令的输入控件；503 场景的说明文案原样带上服务端理由。
// 跑法：node tests/render-check.mjs
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { renderToString } from '@vue/server-renderer';
import { createSSRApp, h } from 'vue';

// 三类 canary：端到端口令、凭据材料本体（含 base64 形态）、凭据库密文。
// 它们只允许存在于测试数据里，任何一处出现在渲染结果中即失败。
const PASSPHRASE = '口令-abcd-1234-绝不出现在页面';
const SECRET_BYTES = '绝不该出现在 DOM 的口令内容';
const SECRET_B64 = Buffer.from(SECRET_BYTES).toString('base64');
const VAULT_B64 = Buffer.from('假私钥字节-锁在端到端信封里').toString('base64');
// 钥匙串账号名与私钥路径：它们确实在客户端上传的清单明文里，但服务端只取 auth 的判别名，
// 这两个值不该出现在 /api/hosts 的响应里，更不该出现在 DOM 里。
const KEYCHAIN_ACCOUNT = 'host-4A2F-MUST-NOT-RENDER';
const KEY_PATH = '/home/dev/.ssh/MUST-NOT-RENDER-id_ed25519';
const CANARIES = [PASSPHRASE, SECRET_BYTES, SECRET_B64, VAULT_B64,
                  KEYCHAIN_ACCOUNT, KEY_PATH];

// GET /api/hosts 的合法行；故意混入服务端绝不会发的凭据字段——
// 渲染层按字段取值，多出来的东西必须像不存在一样。
const hosts = [
  {
    name: '生产 Web-01',
    group: '生产',
    hostname: '10.0.0.1',
    port: 22,
    username: 'root',
    authKind: 'password',
    notes: '机房A，只在晚上动',
    jump: 'ops@bastion.example:22',
    // 判别名以外的 auth 载荷：即便它混进响应对象，渲染层也只取 authKind。
    auth: { password: { secretAccount: KEYCHAIN_ACCOUNT } },
    revision: 9,
    secretMaterial: [{ account: 'host-4A2F', kind: 'password', data: SECRET_B64 }],
    password: SECRET_BYTES,
    passphrase: PASSPHRASE,
  },
  {
    name: '默认 Dev-02',
    group: '默认',
    hostname: '10.0.0.2',
    port: 2222,
    username: 'devops',
    authKind: 'private-key',
    auth: { privateKey: { path: KEY_PATH, passphraseAccount: null } },
    revision: 7,
    secretVault: VAULT_B64,
  },
];

const server = await createServer({
  configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
  server: { middlewareMode: true },
  appType: 'custom',
  logLevel: 'error',
});

function assertClean(html, where) {
  for (const canary of CANARIES) {
    assert.ok(!html.includes(canary), `泄漏：${where} 渲染出了 canary「${canary.slice(0, 12)}…」`);
  }
  for (const pattern of ['deriveKey', 'PBKDF2', 'AES-GCM', 'secretMaterial', 'secretVault', 'passphrase']) {
    assert.ok(!html.includes(pattern), `泄漏：${where} 的标记里出现了「${pattern}」`);
  }
}

try {
  const HostTable = (await server.ssrLoadModule('/src/components/HostTable.vue')).default;
  const tableHtml = await renderToString(createSSRApp({ render: () => h(HostTable, { hosts }) }));
  assert.ok(tableHtml.includes('生产 Web-01'), '主机名要渲染出来');
  assert.ok(tableHtml.includes('10.0.0.2:2222'), '主机:端口要渲染出来');
  assert.ok(tableHtml.includes('devops'), '登录用户要渲染出来');
  assert.ok(tableHtml.includes('分组'), '分组列要在');
  assert.ok(tableHtml.includes('#9'), '来源版本要渲染出来');
  assert.ok(tableHtml.includes('认证方式'), '用户拍板要能看出"是私钥还是密码"，这一列必须在');
  assert.ok(tableHtml.includes('私钥'), 'private-key 要显示成中文「私钥」');
  assert.ok(tableHtml.includes('密码'), 'password 要显示成中文「密码」');
  assert.ok(!tableHtml.includes('keyboard-interactive'), '判别名不许裸显在界面上（必须翻成人话）');
  assert.ok(!tableHtml.includes('MUST-NOT-RENDER'), '账号名与私钥路径即使混进响应也不得进 DOM');
  assert.ok(tableHtml.includes('堡垒机'), '用户拍板要能看出走哪台堡垒机');
  assert.ok(tableHtml.includes('ops@bastion.example:22'), '堡垒机目标要渲染出来');
  assert.ok(tableHtml.includes('机房A，只在晚上动'), '备注要渲染出来（客户端已替隐去含口令的那种）');
  assert.ok(tableHtml.includes('直连'), '没有堡垒机的那行要显示"直连"而不是空白');
  assertClean(tableHtml, 'HostTable');
  console.log('HostTable 渲染通过（元数据在、凭据 canary 不在），长度', tableHtml.length);

  // 空清单是用户最常第一眼看到的界面，它必须自己说清下一步做什么。
  const emptyHtml = await renderToString(
    createSSRApp({ render: () => h(HostTable, { hosts: [] }) }),
  );
  assert.ok(emptyHtml.includes('还没有任何客户端推送过'), '空清单要说明为什么是空的');
  assert.ok(emptyHtml.includes('偏好设置'), '空清单要指到 Mac 客户端的入口');
  assert.ok(emptyHtml.includes('立即同步'), '空清单要给出那一次要做的动作');
  assert.ok(emptyHtml.includes('不需要先启用通道密钥'), '空清单不许再拿通道密钥当借口');
  assertClean(emptyHtml, 'HostTable(空)');

  const HostsNotice = (await server.ssrLoadModule('/src/components/HostsNotice.vue')).default;
  const noticeHtml = await renderToString(
    createSSRApp({ render: () => h(HostsNotice, { reason: '连不上同步服务，请确认地址与网络' }) }),
  );
  assert.ok(noticeHtml.includes('连不上同步服务'), '服务端中文理由要原样转达');
  assert.ok(noticeHtml.includes('永远不会出现在这里'), '要讲死：口令与私钥不进浏览器');
  assert.ok(noticeHtml.includes('认证方式'), '说明要列清到底有哪些元数据字段');
  assert.ok(noticeHtml.includes('概览'), '通道密钥的开关位置要点明');
  // 用户 2026-10-03 改了口径：清单不再"要先有通道密钥才给看"，旧措辞必须绝迹。
  assert.ok(!noticeHtml.includes('只有在服务端启用'), '旧的"必须启用加密传输才能看"口径要消失');
  assert.ok(!noticeHtml.includes('503'), '说明里不该再出现 503 这套说法');
  assert.ok(!noticeHtml.includes('<input'), '说明里不得提供口令输入框');
  assertClean(noticeHtml, 'HostsNotice');
  console.log('HostsNotice 渲染通过（读失败的说明口径正确）');

  const HostsView = (await server.ssrLoadModule('/src/components/HostsView.vue')).default;
  const hostsHtml = await renderToString(createSSRApp({ render: () => h(HostsView) }));
  assert.ok(hostsHtml.includes('主机清单'), '主机页要渲染');
  assert.ok(hostsHtml.includes('/api/hosts'), '要说明清单来源');
  assert.ok(hostsHtml.includes('明文上传'), '要讲清清单本来就是明文字段');
  assert.ok(hostsHtml.includes('不需要先启用通道密钥'), '旧的 503 口径必须已删除');
  assert.ok(!hostsHtml.includes('type="password"'), '主机页不存在任何口令输入控件');
  assert.ok(!hostsHtml.includes('在本地解密'), '本地解密入口必须已删除');
  assertClean(hostsHtml, 'HostsView');
  console.log('HostsView 渲染通过，长度', hostsHtml.length);

  // 片段清单（GET /api/snippets，2026-10-05 拍板）：三行假数据——一行普通、
  // 一行正文是 Mac 端已整句隐去的中文提示（前端必须逐字照显）、一行 params 非空。
  // 口令 canary 塞进契约之外的多余字段，渲染层读了它就红。
  const SnippetTable = (await server.ssrLoadModule('/src/components/SnippetTable.vue')).default;
  const REDACTED = '（正文含疑似口令，已在本机隐去，未上传）';
  const snippets = [
    {
      name: '重启 nginx',
      group: '生产',
      body: 'systemctl restart nginx',
      params: '',
      updatedAt: '2026-10-05T04:00:00Z',
    },
    {
      name: '登一次网关',
      group: '生产',
      body: REDACTED,
      params: 'host,user',
      updatedAt: '2026-10-05T04:10:00Z',
      // 契约里没有这些字段：即便混进响应对象也不得进 DOM。
      password: SECRET_BYTES,
      passphrase: PASSPHRASE,
    },
    {
      name: '看日志',
      group: '默认',
      body: 'journalctl -u nginx -f\n--since today',
      params: '',
      updatedAt: '2026-10-05T04:20:00Z',
      secretVault: VAULT_B64,
    },
  ];
  const snippetHtml = await renderToString(
    createSSRApp({ render: () => h(SnippetTable, { snippets }) }),
  );
  assert.ok(
    snippetHtml.includes('重启 nginx') && snippetHtml.includes('登一次网关') && snippetHtml.includes('看日志'),
    '三行片段都要渲染出来',
  );
  assert.ok(snippetHtml.includes(REDACTED), '隐去正文的中文提示要逐字出现在正文列——前端不判断、不打码、不显示成空');
  assert.ok(snippetHtml.includes('{host}') && snippetHtml.includes('{user}'), '参数列要把 host,user 渲染成 {host} {user} 的读法');
  assert.ok(snippetHtml.includes('—'), 'params 为空的那两行要显示破折号而不是空白');
  assert.ok(!snippetHtml.includes('2026-10-05T04:00:00Z'), '更新时间不许裸显 ISO 原文，要走 formatTime 的本地化格式');
  assert.match(snippetHtml, /\d{4}\/\d{1,2}\/\d{1,2}/, '更新时间要渲染成 zh-CN 本地化日期（不随时区变格式）');
  assert.ok(snippetHtml.includes('snippet-body'), '正文列要挂等宽样式类，多行保留换行');
  assert.ok(!snippetHtml.includes(PASSPHRASE), '口令字面值绝不允许进 DOM');
  assertClean(snippetHtml, 'SnippetTable');
  console.log('SnippetTable 渲染通过（三行齐全、隐去提示逐字、{host} {user} 参数、canary 不在），长度', snippetHtml.length);

  // 空片段清单：功能已经有了，说明必须指去 Mac 端的维护入口，不许说"待实现"。
  const emptySnippetHtml = await renderToString(
    createSSRApp({ render: () => h(SnippetTable, { snippets: [] }) }),
  );
  assert.ok(emptySnippetHtml.includes('片段库'), '空清单要指到 Mac 端「片段库…」的维护入口');
  assert.ok(emptySnippetHtml.includes('菜单栏'), '空清单要点明入口在菜单栏的 Yank 图标');
  assert.ok(emptySnippetHtml.includes('同步过一次'), '空清单要给出那一次要做的动作');
  assert.ok(!emptySnippetHtml.includes('待实现'), '片段功能是已有的，空清单不许写待实现');
  assertClean(emptySnippetHtml, 'SnippetTable(空)');

  const SnippetsNotice = (await server.ssrLoadModule('/src/components/SnippetsNotice.vue')).default;
  const snippetNoticeHtml = await renderToString(
    createSSRApp({ render: () => h(SnippetsNotice, { reason: '连不上同步服务，请确认地址与网络' }) }),
  );
  assert.ok(snippetNoticeHtml.includes('连不上同步服务'), '服务端中文理由要原样转达');
  assert.ok(snippetNoticeHtml.includes('名称、分组、正文与参数'), '说明要列清到底能看到哪些字段');
  assert.ok(snippetNoticeHtml.includes('端到端信封'), '要讲死：口令本体与私钥只在端到端信封里');
  assert.ok(snippetNoticeHtml.includes('整句隐去'), '要讲清那一格中文提示就是隐去正文的全部');
  assert.ok(!snippetNoticeHtml.includes('<input'), '说明里不得提供口令输入框');
  assertClean(snippetNoticeHtml, 'SnippetsNotice');
  console.log('SnippetsNotice 渲染通过（读失败的说明口径正确）');

  const SnippetsView = (await server.ssrLoadModule('/src/components/SnippetsView.vue')).default;
  const snippetsHtml = await renderToString(createSSRApp({ render: () => h(SnippetsView) }));
  assert.ok(snippetsHtml.includes('片段清单'), '片段页要渲染');
  assert.ok(snippetsHtml.includes('/api/snippets'), '要说明清单来源');
  assert.ok(snippetsHtml.includes('明文上传'), '要讲清清单本来就是明文字段');
  assert.ok(!snippetsHtml.includes('type="password"'), '片段页不存在任何口令输入控件');
  assertClean(snippetsHtml, 'SnippetsView');
  console.log('SnippetsView 渲染通过，长度', snippetsHtml.length);

  const LoginView = (await server.ssrLoadModule('/src/components/LoginView.vue')).default;
  const loginHtml = await renderToString(createSSRApp({ render: () => h(LoginView) }));
  assert.ok(loginHtml.includes('注册'), '登录页要能渲染');
  assert.equal(
    (loginHtml.match(/type="password"/g) ?? []).length,
    1,
    '登录页只允许管理端密码这一个密码框',
  );
  assert.ok(loginHtml.includes('不需要你输入同步口令'), '登录页要说明端到端口令与此无关');
  assertClean(loginHtml, 'LoginView');
  console.log('LoginView 渲染通过，长度', loginHtml.length);

  const OverviewView = (await server.ssrLoadModule('/src/components/OverviewView.vue')).default;
  const overviewHtml = await renderToString(createSSRApp({ render: () => h(OverviewView) }));
  assert.ok(overviewHtml.includes('生成配对码'), '概览页要能渲染');
  assert.ok(overviewHtml.includes('已配对设备'), '概览页要有设备区');
  assert.ok(overviewHtml.includes('同步历史'), '概览页要有历史区');
  assert.ok(overviewHtml.includes('加密传输（通道密钥）'), '概览页要能配置通道密钥（不必再重启服务端）');
  assert.ok(overviewHtml.includes('登录口令（管理端）'), '概览页要能改登录口令，不再只能注册新账号');
  assertClean(overviewHtml, 'OverviewView');
  console.log('OverviewView 渲染通过，长度', overviewHtml.length);

  // 改登录口令的卡片：三个密码框、首屏不预填任何东西、文案必须把「管理端口令」与
  // 「端到端口令」分开讲清——混为一谈就会让人以为改这里能换掉 SSH 凭据的加密口令。
  const PasswordCard = (await server.ssrLoadModule('/src/components/PasswordCard.vue')).default;
  const pwHtml = await renderToString(createSSRApp({ render: () => h(PasswordCard) }));
  assert.ok(pwHtml.includes('原口令'), '要有原口令位');
  assert.ok(pwHtml.includes('确认新口令'), '要有确认位，两次不一致要挡在前端');
  assert.equal(
    (pwHtml.match(/type="password"/g) ?? []).length,
    3,
    '口令卡片必须是三个密码框，不能做成明文输入',
  );
  for (const tag of pwHtml.match(/<input[^>]*>/g) ?? []) {
    assert.ok(!/value="[^"]/.test(tag), `口令框不得预填任何内容：${tag}`);
  }
  assert.ok(pwHtml.includes('永远不会进到'), '要说明端到端口令不进这一页');
  assert.ok(pwHtml.includes('其他浏览器上的会话会被退出'), '要提前讲清改密的后果');
  assert.ok(pwHtml.includes('不受影响'), '要说明 Mac 终端的同步不受网页改密影响');
  assert.ok(!pwHtml.includes('至少需要 10 个字符'), '首屏不该凭空挂一条校验错误');
  assertClean(pwHtml, 'PasswordCard');
  console.log('PasswordCard 渲染通过（三密码框、无预填）');

  // HistoryCard 带数据渲染：回退按钮在行上；旧「查看此版本」（喂本地解密的入口）必须消失。
  const HistoryCard = (await server.ssrLoadModule('/src/components/HistoryCard.vue')).default;
  const historyHtml = await renderToString(
    createSSRApp({
      render: () =>
        h(HistoryCard, {
          items: [{ revision: 7, deviceId: 'dev-1', createdAt: '2026-10-01T09:00:00Z', bytes: 1024 }],
          currentRevision: 8,
          busyRevision: 0,
        }),
    }),
  );
  assert.ok(historyHtml.includes('回退到这一版'), '历史行要有回退按钮');
  assert.ok(!historyHtml.includes('查看此版本'), '本地解密已删除，查看历史信封的按钮不该留下');
  assert.ok(historyHtml.includes('1.0 KiB'), '历史行要显示大小');
  assertClean(historyHtml, 'HistoryCard');
  console.log('HistoryCard 渲染通过');

  // 通道密钥卡片：首屏不预填任何密钥，应答里也没有密钥可填——这一页只负责把密钥交出去，
  // 不负责把它显示出来。它现在是"自己定的一句短密码"（不再是粘进来的 64 位十六进制），
  // 所以输入框必须是遮罩式；明文回显等于旁人瞥一眼就能用。
  const ChannelKeyCard = (await server.ssrLoadModule('/src/components/ChannelKeyCard.vue')).default;
  const cardHtml = await renderToString(createSSRApp({ render: () => h(ChannelKeyCard) }));
  assert.ok(cardHtml.includes('加密传输（通道密钥）'), '卡片标题要在');
  assert.ok(cardHtml.includes('读取中…'), '首屏先报读取状态，不假装已启用');
  assert.ok(cardHtml.includes('指纹'), '要有与管理页两端核对的指纹位');
  const cardInputs = cardHtml.match(/<input[^>]*>/g) ?? [];
  assert.equal(cardInputs.length, 1, `卡片上只该有一个输入控件，实际 ${cardInputs.length}`);
  assert.ok(/type="password"/.test(cardHtml), '通道密钥必须是遮罩输入框（星号），不许明文回显');
  assert.ok(cardHtml.includes('至少 8'), '要写明这是一句至少 8 个字的短密码');
  for (const tag of cardInputs) {
    assert.ok(!/value="[^"]/.test(tag), `输入框不得预填任何内容：${tag}`);
  }
  assert.ok(!cardHtml.includes('<input type="checkbox"'), '不该有多余控件');
  assertClean(cardHtml, 'ChannelKeyCard');
  console.log('ChannelKeyCard 渲染通过（遮罩框、无预填、不回显密钥）');

  console.log('全部 DOM 泄漏与渲染断言通过');
} finally {
  await server.close();
}
