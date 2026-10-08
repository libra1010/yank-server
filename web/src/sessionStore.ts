// 会话令牌的落地：刷新页面必须还是登录态（这是用户明确要的），所以令牌不能只留在内存里。
//
// 单独成模块、并把 storage 作为参数注入，是为了让它能被门禁直接演：
// 过期、脏数据、隐私模式（localStorage 抛异常）这几条都不必真开一个浏览器。
//
// 存进去的只有会话令牌。它换不到口令、私钥或信封明文 —— 那两个接口本来就不返回这些，
// 而 /api/hosts 只回元数据，和这个页面显示的东西是同一批。

export type StoredSession = {
  token: string;
  user: string;
  userId: string;
  /** 毫秒时间戳。服务端会话活 12 小时，本地按同一口径记，到期就不必再去试一次 401。 */
  expiresAt: number;
};

export const SESSION_KEY = 'dropterm.session';
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

/** 内存版 storage：隐私模式或配额满时兜底，行为与真 storage 一致，只是刷新就没了。 */
export function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() { return map.size; },
    clear: () => map.clear(),
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    removeItem: (k: string) => { map.delete(k); },
    setItem: (k: string, v: string) => { map.set(k, String(v)); },
  } as Storage;
}

/** 取本页面能用的 storage；浏览器拒绝（无痕模式老写法、被策略禁用）就退回内存版。 */
export function pickStorage(): Storage {
  try {
    const probe = localStorage;
    const k = SESSION_KEY + '.probe';
    probe.setItem(k, '1');
    probe.removeItem(k);
    return probe;
  } catch {
    return memoryStorage();
  }
}

export function saveSession(store: Storage, session: StoredSession): void {
  try {
    store.setItem(SESSION_KEY, JSON.stringify(session));
  } catch {
    // 存不下只影响"刷新后是否还登录"，不影响这次登录本身。
  }
}

export function clearSession(store: Storage): void {
  try {
    store.removeItem(SESSION_KEY);
  } catch {
    /* 已经没地方可写了 */
  }
}

/** 没有会话就返回 null：形状不对、令牌为空、已到期、JSON 是脏的，都算没有。 */
export function loadSession(store: Storage, now: number = Date.now()): StoredSession | null {
  let raw: string | null = null;
  try {
    raw = store.getItem(SESSION_KEY);
  } catch {
    return null;
  }
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    clearSession(store);
    return null;
  }
  const bag = parsed as Partial<StoredSession> | null;
  if (!bag || typeof bag.token !== 'string' || bag.token === '') {
    clearSession(store);
    return null;
  }
  if (typeof bag.expiresAt !== 'number' || bag.expiresAt <= now) {
    clearSession(store);
    return null;
  }
  return { token: bag.token, user: bag.user ?? '', userId: bag.userId ?? '',
           expiresAt: bag.expiresAt };
}

export function sessionOf(token: string, user: string, userId: string,
                          now: number = Date.now()): StoredSession {
  return { token, user, userId, expiresAt: now + SESSION_TTL_MS };
}
