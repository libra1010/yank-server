<script setup lang="ts">
import { onMounted, ref } from 'vue';
import PairCard from './PairCard.vue';
import ChannelKeyCard from './ChannelKeyCard.vue';
import PasswordCard from './PasswordCard.vue';
import DevicesCard from './DevicesCard.vue';
import HistoryCard from './HistoryCard.vue';
import type { DeviceRow, HistoryRow } from '../types';
import {
  ApiError,
  getDevices,
  getHistory,
  getCurrentRevision,
  healthz,
  rollbackTo,
  useSession,
} from '../useApi';

const { user, userId } = useSession();

const health = ref<{ ok: boolean; dialect: string } | null>(null);
const devices = ref<DeviceRow[]>([]);
const history = ref<HistoryRow[]>([]);
const currentRevision = ref(0);
const busyRevision = ref(0);
const error = ref('');
const notice = ref('');
const loaded = ref(false);

// 单个接口挂了不整页白屏：原因记下来，其余照常显示。
async function attempt<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '请求失败，请稍后再试';
    return fallback;
  }
}

async function refresh() {
  error.value = '';
  const [h, d, hist, rev] = await Promise.all([
    attempt(() => healthz(), null),
    attempt(() => getDevices(), [] as DeviceRow[]),
    attempt(() => getHistory(), [] as HistoryRow[]),
    attempt(() => getCurrentRevision(), 0),
  ]);
  health.value = h;
  devices.value = d;
  history.value = hist;
  currentRevision.value = rev;
  loaded.value = true;
}

// 回退只要版本号：POST /api/blob/rollback 由服务端把那一版的密文原样前滚，
// 浏览器从头到尾不接触信封内容，也不需要任何口令。
async function rollback(revision: number) {
  if (!window.confirm(`把服务端内容退回第 ${revision} 版？当前版本会进入历史，随时可以再回来。`)) return;
  error.value = '';
  notice.value = '';
  busyRevision.value = revision;
  try {
    const result = await rollbackTo(revision);
    notice.value = `已回退，服务端现在是第 ${result.revision} 版。`;
    await refresh();
  } catch (e) {
    // 服务端的中文原因原样转达。
    error.value = e instanceof ApiError ? e.message : '回退失败';
  } finally {
    busyRevision.value = 0;
  }
}

onMounted(refresh);
</script>

<template>
  <div>
    <section class="panel">
      <div class="row" style="justify-content: space-between">
        <h2>状态</h2>
        <button :disabled="!loaded" @click="refresh">{{ loaded ? '刷新' : '加载中…' }}</button>
      </div>
      <div class="row">
        <span class="badge" :class="health ? 'ok' : 'bad'">
          同步服务：{{ health ? `在线（${health.dialect}）` : '不可达' }}
        </span>
        <span class="badge">账号：{{ user }}</span>
        <span class="badge mono">用户 ID：{{ userId }}</span>
        <span class="badge">
          当前信封：{{ currentRevision ? `第 ${currentRevision} 版` : '还没有同步过' }}
        </span>
      </div>
      <p v-if="notice" class="msg-ok small">{{ notice }}</p>
      <p v-if="error" class="msg-error" role="alert">{{ error }}</p>
    </section>

    <PairCard />
    <PasswordCard />
    <ChannelKeyCard />
    <DevicesCard :items="devices" @changed="refresh" />
    <HistoryCard
      :items="history"
      :current-revision="currentRevision"
      :busy-revision="busyRevision"
      @rollback="rollback"
    />
  </div>
</template>
