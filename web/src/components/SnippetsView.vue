<script setup lang="ts">
import { onMounted, ref } from 'vue';
import SnippetTable from './SnippetTable.vue';
import SnippetsNotice from './SnippetsNotice.vue';
import { ApiError, fetchSnippets } from '../useApi';
import type { SnippetMeta } from '../types';

const snippets = ref<SnippetMeta[]>([]);
const state = ref<'loading' | 'ready' | 'error'>('loading');
const error = ref('');

async function load() {
  state.value = 'loading';
  error.value = '';
  try {
    snippets.value = await fetchSnippets();
    state.value = 'ready';
  } catch (e) {
    // 服务端的中文原因原样交给 SnippetsNotice 转达，与主机清单一棵树上的写法。
    error.value = e instanceof ApiError ? e.message : '读取片段清单失败，请稍后再试';
    snippets.value = [];
    state.value = 'error';
  }
}

onMounted(load);
</script>

<template>
  <div>
    <section class="panel">
      <div class="row" style="justify-content: space-between">
        <h2>片段清单</h2>
        <button :disabled="state === 'loading'" @click="load">
          {{ state === 'loading' ? '读取中…' : '重新读取' }}
        </button>
      </div>
      <p class="muted small">
        这份清单来自服务端的元数据接口 <span class="mono">GET /api/snippets</span>，字段是名称、分组、
        正文、参数与更新时间。这些是 Mac 客户端<strong>明文上传的片段库内容</strong>，
        不需要先启用通道密钥就能看。这里能看到的是片段的名称、分组、正文与参数；
        <strong>口令本体与私钥永远只在端到端信封里，服务端和浏览器都读不到</strong>；
        疑似含口令的正文在 Mac 上就被整句隐去，所以那一格出现的中文提示就是它的全部。
      </p>
      <p v-if="state === 'ready' && !snippets.length" class="muted small">
        这个账号还没有同步过任何片段。片段在 Mac 端菜单栏的 Yank 图标 ▸「片段库…」里维护，
        同步过一次之后这里就会出现。
      </p>

      <div v-if="state === 'loading'" class="muted small">正在读取片段清单…</div>
      <SnippetsNotice v-else-if="state === 'error'" :reason="error" />
      <SnippetTable v-else :snippets="snippets" />
    </section>
  </div>
</template>
