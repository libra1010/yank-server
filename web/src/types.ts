// 数据契约：只描述管理端允许接触的东西。
// 浏览器看不到端到端信封的明文：主机清单只来自服务端已解密的元数据接口 GET /api/hosts，
// 其字段是服务端白名单（名称/分组/主机/端口/用户），根本不含凭据本体。
// 片段清单同理，来自 GET /api/snippets：只有名称、分组、正文、参数、更新时间五个字段，
// 正文在 Mac 端已嗅探——疑似含口令的整句隐去后才上传。
// 因此这里不存在描述信封明文的类型：清单明文、凭据材料、凭据库一类字段一律不在此建模，
// 也不允许出现在任何渲染路径（tests/gate.mjs 把守）。

/** GET /api/hosts 的一行：服务端从加密传输通道里索引出的主机元数据（SPEC §6）。 */
export interface HostMeta {
  name: string;
  group: string;
  hostname: string;
  port: number;
  username: string;
  /** 认证方式的判别名（password / keyboard-interactive / private-key / agent）；空串表示客户端没告知。
   *  只有"是哪一种"，永远不含账号名、私钥路径、口令。 */
  authKind: string;
  /** 操作者自己写的备注。客户端在上传前会把"password: 真东西"这类内容整条隐去。 */
  notes: string;
  /** 这台主机经由的堡垒机（"ops@bastion:22"）；直连为空串。 */
  jump: string;
  /** 这一行来自哪一版信封 */
  revision: number;
}

/**
 * GET /api/snippets 的一行：Mac 端代码片段库明文上传的元数据（2026-10-05 拍板）。
 * body 已经过客户端嗅探——疑似含口令的条目在 Mac 上就被整句换成中文提示，过长同理；
 * 前端照原样显示那句文本，不判断、不打码、不显示成空。
 * params 是逗号分隔的占位符名（如 "host,user"），空串表示没有参数。
 */
export interface SnippetMeta {
  name: string;
  group: string;
  body: string;
  params: string;
  /** ISO8601 字符串，渲染走 formatTime 的本地化格式 */
  updatedAt: string;
}

export interface DeviceRow {
  id: string;
  name: string;
  createdAt: string;
  lastSeen: string | null;
  revoked: boolean;
}

export interface HistoryRow {
  revision: number;
  deviceId: string;
  createdAt: string;
  bytes: number;
}

export interface PairResult {
  code: string;
  expiresIn: number;
  note: string;
}

/**
 * GET /api/channel 的应答：通道口令的存在性，不含口令本身。
 * 服务端只肯给指纹（SHA-256 前 3 字节），所以这个类型里没有任何可泄漏的秘密。
 */
export interface ChannelState {
  enabled: boolean;
  /** page=本页配置，none=未启用（启动参数那一路已经删掉了） */
  source: 'page' | 'none';
  fingerprint: string;
}
