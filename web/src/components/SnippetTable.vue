<script setup lang="ts">
import { computed } from 'vue';
import type { SnippetMeta } from '../types';
import { formatTime } from '../format';

const props = defineProps<{ snippets: SnippetMeta[] }>();

// 列到 GET /api/snippets 的五个字段为止：名称/分组/正文/参数/更新时间。
// 正文照原样显示：客户端上传前已嗅探，疑似含口令或过长的条目整句换成了中文提示，
// 前端不判断、不打码、不显示成空。
function paramsText(params: string): string {
  const names = params.split(',').map((p) => p.trim()).filter(Boolean);
  return names.length ? names.map((p) => `{${p}}`).join(' ') : '—';
}

const rows = computed(() =>
  [...props.snippets].sort(
    (a, b) => a.group.localeCompare(b.group, 'zh-CN') || a.name.localeCompare(b.name, 'zh-CN'),
  ),
);
</script>

<template>
  <div>
    <div v-if="!props.snippets.length" class="muted small">
      片段库里还没有内容。片段在 Mac 端菜单栏的 Yank 图标 ▸「片段库…」里维护，
      同步过一次之后这里就会出现。
    </div>
    <div v-else class="tablewrap">
      <table>
        <thead>
          <tr>
            <th>名称</th><th>分组</th><th>正文</th><th>参数</th><th>更新时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(s, i) in rows" :key="`${s.group}-${s.name}-${i}`">
            <td data-label="名称">{{ s.name }}</td>
            <td data-label="分组">{{ s.group }}</td>
            <td data-label="正文"><div class="snippet-body">{{ s.body }}</div></td>
            <td data-label="参数" class="mono">{{ paramsText(s.params) }}</td>
            <td data-label="更新时间">{{ formatTime(s.updatedAt) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
