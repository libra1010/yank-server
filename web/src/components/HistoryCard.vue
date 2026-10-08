<script setup lang="ts">
import type { HistoryRow } from '../types';
import { formatBytes, formatTime } from '../format';

const props = defineProps<{ items: HistoryRow[]; currentRevision: number; busyRevision: number }>();
const emit = defineEmits<{
  (e: 'rollback', revision: number): void;
}>();
</script>

<template>
  <section class="panel">
    <h2>同步历史</h2>
    <p class="muted small">
      服务端保留历史信封（对浏览器始终是不透明的密文），所以任何一次自动合并都能退回去。
      「回退到这一版」只告诉服务端要第几版，由它把那份密文原样前滚，浏览器不需要任何口令。
    </p>
    <div v-if="!props.items.length" class="muted small">还没有任何同步记录。</div>
    <div v-else class="tablewrap">
      <table>
        <thead>
          <tr><th>版本</th><th>时间</th><th>大小</th><th>写入设备</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="row in props.items" :key="row.revision">
            <td data-label="版本">
              <span class="mono">#{{ row.revision }}</span>
              <span v-if="row.revision === props.currentRevision" class="badge ok" style="margin-left: 6px">当前</span>
            </td>
            <td data-label="时间">{{ formatTime(row.createdAt) }}</td>
            <td data-label="大小">{{ formatBytes(row.bytes) }}</td>
            <td data-label="写入设备" class="mono">{{ row.deviceId }}</td>
            <td data-label="操作">
              <div class="row">
                <button
                  class="danger"
                  :disabled="row.revision === props.currentRevision || props.busyRevision !== 0"
                  @click="emit('rollback', row.revision)"
                >
                  {{ props.busyRevision === row.revision ? '回退中…' : '回退到这一版' }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
