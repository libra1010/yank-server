// 会话接线的端到端：不测工具函数，测 useApi.ts 这个真模块在"登录 → 刷新 → 退出"
// 三个时刻到底做了什么。浏览器在这里被三样东西替掉：一个假 localStorage、一个假 fetch、
// 以及 vite 的模块缓存失效（等价于重新加载页面）。
//
// 为什么值得单独一条：sessionRefresh.mjs 演的是 storage 那一层的规则，而"规则写对了但
// 没接到登录按钮上"恰恰是用户这次报的那种缺陷。跑法：node tests/sessionWiring.mjs
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

function fakeStorage() {
  const map = new Map();
  return {
    get length() { return map.size; },
    clear: () => map.clear(),
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    key: (i) => Array.from(map.keys())[i] ?? null,
    removeItem: (k) => { map.delete(k); },
    setItem: (k, v) => { map.set(k, String(v)); },
    _map: map,
  };
}

// 唯一的真接口行为：/api/login 发一张令牌，其余请求一律 200。令牌是否被带上，
// 由这里记账，用来断言"刷新后用的还是同一张"。
const sent = { authorization: [] };
globalThis.fetch = async (url, init = {}) => {
  const headers = new Headers(init.headers ?? {});
  sent.authorization.push(headers.get('authorization') ?? '');
  if (String(url).endsWith('/api/login')) {
    return new Response(JSON.stringify({ token: 'tok-real-1', userId: 'u-1', user: 'admin' }),
      { status: 200, headers: { 'content-type': 'application/json' } });
  }
  if (String(url).endsWith('/api/logout')) {
    return new Response(null, { status: 204 });
  }
  return new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } });
};

const store = fakeStorage();
globalThis.localStorage = store;

const server = await createServer({
  configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
  server: { middlewareMode: true },
  appType: 'custom',
  logLevel: 'error',
});

const SESSION_KEY = 'dropterm.session';

try {
  // ① 刚打开页面：盘上什么都没有 → 必须是登录页，而不是"看着登录了、一请求就 401"。
  let api = await server.ssrLoadModule('/src/useApi.ts');
  assert.equal(api.useSession().loggedIn.value, false, '空盘不该被当成已登录');

  // ② 登录：令牌既要进内存，也要进盘。
  await api.login('admin', 'a-long-enough-pass');
  assert.equal(api.useSession().loggedIn.value, true, '登录后应算已登录');
  assert.ok(store._map.has(SESSION_KEY), '登录后盘上没有令牌 —— 刷新必然掉回登录页');
  const written = JSON.parse(store.getItem(SESSION_KEY));
  assert.equal(written.token, 'tok-real-1', '存进去的就是服务端刚发的那张');

  // ③ 刷新：模块重新加载（内存全丢），只许从盘上把登录态捞回来。
  await server.moduleGraph.invalidateAll();
  api = await server.ssrLoadModule('/src/useApi.ts');
  assert.equal(api.useSession().loggedIn.value, true, '刷新之后掉回了登录页（用户报的就是这条）');
  assert.equal(api.useSession().user.value, 'admin', '刷新后还应知道是谁');
  assert.equal(api.useSession().userId.value, 'u-1');

  // 刷新后发出的第一个请求必须带着那张恢复出来的令牌，否则"登录态"只是界面上的假象。
  await api.getChannelState();
  const last = sent.authorization[sent.authorization.length - 1];
  assert.equal(last, 'Bearer tok-real-1', `刷新后的请求没带原令牌：${last}`);
  console.log('登录 → 刷新 → 仍带着同一张令牌');

  // ④ 退出：内存和盘必须一起清掉，否则下一次刷新又"自己登录"回去。
  api.logout();
  assert.equal(api.useSession().loggedIn.value, false);
  assert.equal(store._map.has(SESSION_KEY), false, '退出后盘上还留着令牌');

  // ⑤ 反例：服务端已经换了新令牌，盘上不能还是旧的（登录必须覆盖写）。
  await server.moduleGraph.invalidateAll();
  api = await server.ssrLoadModule('/src/useApi.ts');
  store.setItem(SESSION_KEY, JSON.stringify({ token: 'tok-stale', user: 'x', userId: 'x',
                                              expiresAt: Date.now() + 3600_000 }));
  await server.moduleGraph.invalidateAll();
  api = await server.ssrLoadModule('/src/useApi.ts');
  assert.equal(api.useSession().token.value, 'tok-stale', '脏场景没被恢复出来');
  await api.login('admin', 'a-long-enough-pass');
  assert.equal(JSON.parse(store.getItem(SESSION_KEY)).token, 'tok-real-1',
    '重新登录后盘上仍是旧令牌');
  console.log('退出真的清盘、重新登录真的换令牌');

  console.log('会话接线断言全部通过');
} finally {
  await server.close();
}
