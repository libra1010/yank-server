// 刷新页面还算不算登录态。用户的话是「一刷新就回到登录页，这样不对」，
// 所以这条门禁用真模块（vite 的 SSR 通道加载 sessionStore.ts）演一遍浏览器的生命周期：
// 登录 → 写盘 → "刷新"（重新读盘）→ 还在登录；到期/脏数据/退出 → 必须回登录页，
// 而不是拿着一个服务端已经认不出的令牌卡在界面上。
//
// storage 是注入的假对象，所以无痕模式、localStorage 被禁、配额满都能在这里演，
// 不必真开浏览器。跑法：node tests/sessionRefresh.mjs
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

function fakeStorage({ throwOnRead = false, throwOnWrite = false } = {}) {
  const map = new Map();
  return {
    get length() { return map.size; },
    clear: () => map.clear(),
    getItem: (k) => { if (throwOnRead) throw new Error('SecurityError'); return map.has(k) ? map.get(k) : null; },
    key: (i) => Array.from(map.keys())[i] ?? null,
    removeItem: (k) => { if (throwOnWrite) throw new Error('SecurityError'); map.delete(k); },
    setItem: (k, v) => { if (throwOnWrite) throw new Error('QuotaExceeded'); map.set(k, String(v)); },
    _dump: () => new Map(map),
  };
}

const server = await createServer({
  configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
  server: { middlewareMode: true },
  appType: 'custom',
  logLevel: 'error',
});

const mod = await server.ssrLoadModule('/src/sessionStore.ts');
const { SESSION_KEY, SESSION_TTL_MS, saveSession, loadSession, clearSession, sessionOf,
        memoryStorage, pickStorage } = mod;

const NOW = 1_700_000_000_000;

try {
  // 1) 登录 → 写盘 → 刷新（重新读盘）→ 还是登录态，而且带的还是那个人。
  const store = fakeStorage();
  saveSession(store, sessionOf('tok-1', 'admin', 'u-1', NOW));
  const afterRefresh = loadSession(store, NOW + 1000);
  assert.ok(afterRefresh, '刷新之后必须还在登录');
  assert.equal(afterRefresh.token, 'tok-1', '刷新后用的还是同一张令牌');
  assert.equal(afterRefresh.user, 'admin');
  assert.equal(afterRefresh.userId, 'u-1');
  assert.equal(afterRefresh.expiresAt, NOW + SESSION_TTL_MS, '期限要跟服务端同款（12 小时）');
  assert.equal(SESSION_TTL_MS, 12 * 60 * 60 * 1000);
  console.log('刷新保持登录通过');

  // 2) 反例：退出登录必须把盘上的令牌一起抹掉，只清内存等于下次刷新又"自动登录"回去。
  clearSession(store);
  assert.equal(store._dump().has(SESSION_KEY), false, '盘上仍留着令牌');
  assert.equal(loadSession(store, NOW), null, '退出后不该恢复出会话');
  console.log('退出真的清盘通过');

  // 3) 到期：不再拿去试（服务端那张令牌早失效了），并且顺手抹干净。
  const stale = fakeStorage();
  saveSession(stale, sessionOf('tok-old', 'admin', 'u-1', NOW));
  assert.equal(loadSession(stale, NOW + SESSION_TTL_MS + 1), null, '过期的会话不该恢复');
  assert.equal(stale._dump().has(SESSION_KEY), false, '过期令牌该被清掉，不该留着每次撞 401');
  console.log('到期自动回登录页通过');

  // 4) 盘上是脏东西 / 形状不对 / 令牌为空 —— 一律当没登录，且不许抛。
  for (const [label, value] of [['脏 JSON', '{不是JSON'], ['不是对象', '"字符串"'],
       ['空令牌', '{"token":"","expiresAt":9e15}'],
       ['没有期限', '{"token":"t"}'],
       ['期限是字符串', '{"token":"t","expiresAt":"9000000000000"}']]) {
    const dirty = fakeStorage();
    dirty.setItem(SESSION_KEY, value);
    assert.equal(loadSession(dirty, NOW), null, `${label} 应被当作没有会话`);
  }
  console.log('脏数据全部退回登录页通过');

  // 5) 无痕模式或 localStorage 被策略禁用：读写都抛异常时，页面不许因此打不开。
  const hostile = fakeStorage({ throwOnRead: true, throwOnWrite: true });
  assert.equal(loadSession(hostile, NOW), null);
  saveSession(hostile, sessionOf('tok', 'admin', 'u', NOW)); // 不该抛
  clearSession(hostile);
  const mem = memoryStorage();
  saveSession(mem, sessionOf('tok-mem', 'admin', 'u-9', NOW));
  assert.equal(loadSession(mem, NOW).token, 'tok-mem', '内存兜底至少撑住这一次会话');
  console.log('storage 抛异常时退回内存、不崩通过');

  // 6) pickStorage 在无 window/localStorage 的环境（SSR、门禁）里也必须给一个能用的对象。
  const picked = pickStorage();
  saveSession(picked, sessionOf('tok-pick', 'admin', 'u', NOW));
  assert.equal(loadSession(picked, NOW).token, 'tok-pick');
  console.log('pickStorage 兜底通过');

  console.log('全部会话持久化断言通过');
} finally {
  await server.close();
}
