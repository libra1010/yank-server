<script setup lang="ts">
import { onMounted, ref } from 'vue';
import HostTable from './HostTable.vue';
import HostsNotice from './HostsNotice.vue';
import { ApiError, getHosts } from '../useApi';
import type { HostMeta } from '../types';

const hosts = ref<HostMeta[]>([]);
const state = ref<'loading' | 'ready' | 'error'>('loading');
const error = ref('');

async function load() {
  state.value = 'loading';
  error.value = '';
  try {
    hosts.value = await getHosts();
    state.value = 'ready';
  } catch (e) {
    // 服务端的中文原因（如「未启用加密传输」）原样交给 HostsNotice 转达。
    error.value = e instanceof ApiError ? e.message : '读取主机清单失败，请稍后再试';
    hosts.value = [];
    state.value = 'error';
  }
}

onMounted(load);
</script>

<template>
  <div>
    <section class="panel">
      <div class="row" style="justify-content: space-between">
        <h2>主机清单</h2>
        <button :disabled="state === 'loading'" @click="load">
          {{ state === 'loading' ? '读取中…' : '重新读取' }}
        </button>
      </div>
      <p class="muted small">
        这份清单来自服务端的元数据接口 <span class="mono">GET /api/hosts</span>，字段是名称、分组、
        主机:端口、登录用户、认证方式（密码还是私钥）、备注、堡垒机与来源版本。
        这些是 Mac 客户端<strong>明文上传的元数据</strong>，不需要先启用通道密钥就能看；
        而口令、私钥内容、钥匙串账号名从来不在这份数据里——
        浏览器和服务端都拿不到它们，这个页面也不接收端到端口令。
      </p>
      <p v-if="state === 'ready' && !hosts.length" class="muted small">
        这个账号还没有任何客户端推送过清单。在 Mac 上打开 Yank 的「偏好设置 ▸ 凭据同步」，
        点一次「立即同步」，这里就会列出上面那些字段。
      </p>

      <div v-if="state === 'loading'" class="muted small">正在读取主机清单…</div>
      <HostsNotice v-else-if="state === 'error'" :reason="error" />
      <HostTable v-else :hosts="hosts" />
    </section>
  </div>
</template>
