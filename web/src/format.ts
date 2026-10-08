// 展示层的小工具：中文文案 + 本地化时间/体积。不含任何秘密，也不引用任何清单结构。
export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(2)} MiB`;
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return '—';
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return value;
  return at.toLocaleString('zh-CN', { hour12: false });
}

export function relativeFromNow(value: string | null | undefined): string {
  if (!value) return '从未同步';
  const at = new Date(value).getTime();
  if (Number.isNaN(at)) return '—';
  const diff = Date.now() - at;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)} 分钟前`;
  if (diff < 3_600_000 * 24) return `${Math.round(diff / 3_600_000)} 小时前`;
  if (diff < 30 * 86_400_000) return `${Math.round(diff / 86_400_000)} 天前`;
  return formatTime(value);
}
