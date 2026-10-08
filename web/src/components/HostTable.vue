<script setup lang="ts">
import { computed, ref } from 'vue';
import type { HostMeta } from '../types';

const props = defineProps<{ hosts: HostMeta[] }>();
const needle = ref('');

// 列到 GET /api/hosts 白名单字段为止：名称/分组/主机:端口/用户/认证方式/备注/堡垒机/来源版本。
// 这些是客户端**明文**上传的元数据（SPEC §5.1），不需要通道密钥就能看；
// 口令、私钥内容、钥匙串账号名在这条链路上根本不存在。
const AUTH_LABELS: Record<string, string> = {
  password: '密码',
  'keyboard-interactive': '键盘交互（口令）',
  'private-key': '私钥',
  agent: 'ssh-agent（无口令）',
};

function authLabel(kind: string): string {
  return AUTH_LABELS[kind] ?? '未知';
}

function haystack(host: HostMeta): string {
  return [host.name, host.group, host.hostname, host.username, String(host.port),
          authLabel(host.authKind), host.authKind, host.notes, host.jump]
    .join('\n')
    .toLowerCase();
}

const rows = computed(() => {
  const sorted = [...props.hosts].sort(
    (a, b) => a.group.localeCompare(b.group, 'zh-CN') || a.name.localeCompare(b.name, 'zh-CN'),
  );
  const key = needle.value.trim().toLowerCase();
  if (!key) return sorted;
  return sorted.filter((host) => haystack(host).includes(key));
});
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 10px">
      <label class="field" style="max-width: 320px">
        <span>筛选（名称 / 主机 / 用户 / 分组 / 认证方式）</span>
        <input v-model="needle" type="search" placeholder="输入关键字" />
      </label>
      <span class="muted small">显示 {{ rows.length }} / {{ props.hosts.length }} 台</span>
    </div>

    <div v-if="!props.hosts.length" class="muted small">
      清单里还没有主机。这个账号还没有任何客户端推送过元数据 —— 在 Mac 上打开 Yank 的
      「偏好设置 ▸ 凭据同步」，点一次「立即同步」，这里就会列出名称、主机:端口、用户、
      认证方式、备注与堡垒机。<strong>这一步不需要先启用通道密钥。</strong>
    </div>
    <div v-else-if="!rows.length" class="muted small">没有匹配的主机。</div>
    <div v-else class="tablewrap">
      <table>
        <thead>
          <tr>
            <th>名称</th><th>分组</th><th>主机:端口</th><th>用户</th><th>认证方式</th><th>备注</th><th>堡垒机</th><th>来源版本</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(host, i) in rows" :key="`${host.name}-${host.hostname}-${i}`">
            <td data-label="名称">{{ host.name }}</td>
            <td data-label="分组">{{ host.group }}</td>
            <td data-label="主机:端口" class="mono">{{ host.hostname }}:{{ host.port }}</td>
            <td data-label="用户" class="mono">{{ host.username }}</td>
            <td data-label="认证方式">{{ authLabel(host.authKind) }}</td>
            <td data-label="备注">{{ host.notes || '—' }}</td>
            <td data-label="堡垒机" class="mono">{{ host.jump || '直连' }}</td>
            <td data-label="来源版本" class="mono">#{{ host.revision }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
