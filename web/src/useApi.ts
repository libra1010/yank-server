// API 客户端 + 会话。会话令牌落在 localStorage，并带着服务端同款 12 小时期限：
// 刷新页面必须还是登录态（这是用户明确要的），到期或收到 401 就自动回登录页。
//
// 三条口径写在明处：
// 1) 管理端永远不读信封内容。GET /api/blob 的响应体在这里被直接取消（不读进内存），
//    只从 ETag 头拿当前版本号。
// 2) 主机清单只来自 GET /api/hosts。它是服务端一直可读的明文元数据（名称、地址、端口、
//    登录用户、认证方式、备注、堡垒机），与通道密钥是否启用无关；口令与私钥永远不在里面。
// 3) 代码片段只来自 GET /api/snippets（名称、分组、正文、参数、更新时间）。正文在 Mac 端
//    已嗅探：疑似含口令的整句在本机隐去后才上传；口令本体与私钥永远只在端到端信封里。
//
// 存进 localStorage 的只有会话令牌：它换不到口令、私钥或信封明文（那两个接口本来就不返回），
// 它能换到的东西与这个页面显示的东西是同一批元数据。
import { computed, ref } from 'vue';
import { clearSession, loadSession, pickStorage, saveSession, sessionOf } from './sessionStore';
import type { ChannelState, DeviceRow, HistoryRow, HostMeta, PairResult, SnippetMeta } from './types';

export class ApiError extends Error {
  status: number;
  constructor(status: number, reason: string) {
    super(reason);
    this.status = status;
  }
}

const token = ref('');
const user = ref('');
const userId = ref('');

// 会话落地在 sessionStore.ts（可注入 storage，所以能被门禁演）。这里只负责把恢复出来的
// 状态灌进响应式变量，以及让"退出"和"401"两条路都把令牌抹掉。
const storage = pickStorage();

const restored = loadSession(storage);
if (restored) {
  token.value = restored.token;
  user.value = restored.user;
  userId.value = restored.userId;
}

function remember(): void {
  if (!token.value) return;
  saveSession(storage, sessionOf(token.value, user.value, userId.value));
}

const loggedIn = computed(() => token.value !== '');

type Auth = 'none' | 'session';

async function call<T>(path: string, init: RequestInit = {}, auth: Auth = 'session'): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }
  if (auth !== 'none' && token.value) headers.set('authorization', `Bearer ${token.value}`);
  let res: Response;
  try {
    res = await fetch(path, { ...init, headers });
  } catch {
    throw new ApiError(0, '连不上同步服务，请确认地址与网络');
  }
  if (res.status === 204) return null as T;
  const text = await res.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }
  if (!res.ok) {
    // 服务端的 reason 本来就是中文，原样转达，不改写、不吞掉。
    const reason =
      (payload as { reason?: string } | null)?.reason ?? `请求失败（HTTP ${res.status}）`;
    // 会话类接口回 401 说明令牌已失效，把人踢下线；'none'/'session' 之外的口径已不存在。
    if (res.status === 401 && auth === 'session' && token.value) logout();
    throw new ApiError(res.status, reason);
  }
  return (payload ?? null) as T;
}

export async function register(name: string, password: string): Promise<void> {
  const res = await call<{ userId: string; user: string }>(
    '/api/register',
    { method: 'POST', body: JSON.stringify({ user: name, password }) },
    'none',
  );
  userId.value = res.userId;
  user.value = res.user;
}

export async function login(name: string, password: string): Promise<void> {
  const res = await call<{ token: string; userId: string; user: string }>(
    '/api/login',
    { method: 'POST', body: JSON.stringify({ user: name, password }) },
    'none',
  );
  token.value = res.token;
  userId.value = res.userId;
  user.value = res.user;
  remember();
}

export function logout(): void {
  if (token.value) void call('/api/logout', { method: 'POST' }).catch(() => undefined);
  token.value = '';
  user.value = '';
  userId.value = '';
  clearSession(storage);
}

export async function createPairCode(): Promise<PairResult> {
  return call<PairResult>('/api/pair', { method: 'POST' });
}

/**
 * 当前版本号，只要 GET /api/blob 的 ETag。响应体是端到端密文，管理端读它没有任何用处，
 * 所以这里直接把 body 取消掉：浏览器连密文的字节都不碰。
 * 返回 0 表示服务端还没有任何信封。
 */
export async function getCurrentRevision(): Promise<number> {
  const headers = new Headers();
  if (token.value) headers.set('authorization', `Bearer ${token.value}`);
  const res = await fetch('/api/blob', { headers }).catch(() => {
    throw new ApiError(0, '连不上同步服务，请确认地址与网络');
  });
  if (res.status === 204) return 0;
  if (!res.ok) {
    // 出错时响应体只是一句 {"reason":"…"}，读它；成功时的信封绝不读。
    const text = await res.text().catch(() => '');
    let reason = `读取失败（HTTP ${res.status}）`;
    try {
      reason = (JSON.parse(text) as { reason?: string }).reason ?? reason;
    } catch {
      /* 保留默认文案 */
    }
    if (res.status === 401 && token.value) logout();
    throw new ApiError(res.status, reason);
  }
  await res.body?.cancel().catch(() => undefined);
  return Number(res.headers.get('etag')?.replace(/"/g, '') ?? 0);
}

/**
 * GET /api/hosts：服务端一直可读的明文主机元数据，裸 JSON 数组，没有就是 []。
 * 这一页不需要先启用通道密钥——清单与信封是两条独立的路，服务端只见到白名单字段。
 */
export async function getHosts(): Promise<HostMeta[]> {
  const rows = await call<HostMeta[]>('/api/hosts');
  return rows ?? [];
}

/**
 * GET /api/snippets：Mac 端代码片段库明文上传的元数据（2026-10-05 拍板），
 * 裸 JSON 数组，没有就是 []（不是错误）。鉴权与 GET /api/hosts 完全同权，走同一条错误路径。
 * body 已经过客户端嗅探：疑似含口令或过长的条目在上传前就被整句换成中文提示，页面照原样显示。
 */
export async function fetchSnippets(): Promise<SnippetMeta[]> {
  const rows = await call<SnippetMeta[]>('/api/snippets');
  return rows ?? [];
}

export async function getHistory(): Promise<HistoryRow[]> {
  const res = await call<{ items: HistoryRow[] }>('/api/blob/history');
  return res.items ?? [];
}

export async function getDevices(): Promise<DeviceRow[]> {
  const res = await call<{ items: DeviceRow[] }>('/api/devices');
  return res.items ?? [];
}

export async function revokeDevice(deviceId: string): Promise<void> {
  await call<{ ok: boolean }>('/api/devices/revoke', {
    method: 'POST',
    body: JSON.stringify({ deviceId }),
  });
}

/**
 * 回退：POST /api/blob/rollback {"revision":N} → 200 {"revision":新版本}。
 * 服务端把历史里那一版的密文原样前滚，它自己读不懂内容，所以浏览器不需要任何口令。
 * 写入类接口用会话令牌，绝不再碰只认设备令牌的 PUT /api/blob。
 */
export async function rollbackTo(revision: number): Promise<{ revision: number }> {
  return call<{ revision: number }>('/api/blob/rollback', {
    method: 'POST',
    body: JSON.stringify({ revision }),
  });
}

export async function healthz(): Promise<{ ok: boolean; dialect: string }> {
  return call<{ ok: boolean; dialect: string }>('/api/healthz', {}, 'none');
}

/**
 * GET /api/channel：传输层通道密钥的当前状态。服务端只报存在性与指纹，永不回传密钥，
 * 所以这条链路上没有可显示、可复制、可进日志的秘密。
 */
export async function getChannelState(): Promise<ChannelState> {
  return call<ChannelState>('/api/channel');
}

/**
 * POST /api/channel：保存或（空串）清除本页配置的通道密钥（一句自己定的短密码，至少 8 个字）。
 * 这是「让服务端解开外层信封读主机清单」的开关，与端到端口令无关：
 * 那把口令从不经过这里，也不落在这个页面的任何控件里。
 * 返回写入后的最新状态，调用方据此刷新指纹行。
 */
export async function setChannelKey(key: string): Promise<ChannelState> {
  return call<ChannelState>('/api/channel', { method: 'POST', body: JSON.stringify({ key }) });
}

/**
 * 修改「浏览器登录这个管理端」用的口令，与保护 SSH 凭据的端到端口令无关。
 * POST /api/password {"oldPassword","newPassword"} → 200 {"reason":"…"}。
 * 服务端只收原口令与新口令两样，回包里没有任何口令；改完之后本账号在别处的会话全部作废。
 */
export async function changePassword(
  oldPassword: string,
  newPassword: string,
): Promise<{ reason: string }> {
  return call<{ reason: string }>('/api/password', {
    method: 'POST',
    body: JSON.stringify({ oldPassword, newPassword }),
  });
}

export function useSession() {
  return { token, user, userId, loggedIn };
}
