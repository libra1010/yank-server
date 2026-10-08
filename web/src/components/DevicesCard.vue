<script setup lang="ts">
import { ref } from 'vue';
import type { DeviceRow } from '../types';
import { ApiError, revokeDevice } from '../useApi';
import { formatTime, relativeFromNow } from '../format';

const props = defineProps<{ items: DeviceRow[] }>();
const emit = defineEmits<{ (e: 'changed'): void }>();

const busyId = ref('');
const error = ref('');

async function revoke(device: DeviceRow) {
  if (!window.confirm(`确定吊销「${device.name}」？这台 Mac 之后无法再同步。`)) return;
  error.value = '';
  busyId.value = device.id;
  try {
    await revokeDevice(device.id);
    emit('changed');
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '吊销失败';
  } finally {
    busyId.value = '';
  }
}
</script>

<template>
  <section class="panel">
    <h2>已配对设备</h2>
    <p class="muted small">设备标识与活动时间是这里的设备信息；信封内容对服务端是密文，口令与私钥对这个浏览器永远不可见。</p>
    <div v-if="!props.items.length" class="muted small">还没有设备。上面的配对码可以用。</div>
    <div v-else class="tablewrap">
      <table>
        <thead>
          <tr><th>名称</th><th>设备编号</th><th>配对时间</th><th>最近活动</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="device in props.items" :key="device.id">
            <td data-label="名称">{{ device.name || '未命名设备' }}</td>
            <td data-label="设备编号" class="mono">{{ device.id }}</td>
            <td data-label="配对时间">{{ formatTime(device.createdAt) }}</td>
            <td data-label="最近活动">
              <span v-if="device.revoked" class="badge bad">已吊销</span>
              <span v-else>{{ relativeFromNow(device.lastSeen) }}</span>
            </td>
            <td>
              <button
                v-if="!device.revoked"
                class="danger"
                :disabled="busyId === device.id"
                @click="revoke(device)"
              >
                {{ busyId === device.id ? '处理中…' : '吊销' }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-if="error" class="msg-error" role="alert">{{ error }}</p>
  </section>
</template>
