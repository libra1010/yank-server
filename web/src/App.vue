<script setup lang="ts">
import { ref, watch } from 'vue';
import LoginView from './components/LoginView.vue';
import OverviewView from './components/OverviewView.vue';
import HostsView from './components/HostsView.vue';
import SnippetsView from './components/SnippetsView.vue';
import BrandMark from './components/BrandMark.vue';
import { logout, useSession } from './useApi';

const { loggedIn, user } = useSession();
const tab = ref<'overview' | 'hosts' | 'snippets'>('overview');

// 退出登录后回到概览；管理端令牌本身在 useApi 里已被丢弃。
watch(loggedIn, (stillIn) => {
  if (!stillIn) tab.value = 'overview';
});

function signOut() {
  logout();
}
</script>

<template>
  <div v-if="!loggedIn" class="wrap">
    <LoginView />
  </div>

  <div v-else class="wrap">
    <header class="row" style="justify-content: space-between; margin-bottom: 16px">
      <div class="row">
        <h1 class="brand"><BrandMark :size="26" /> Yank 同步管理端</h1>
        <span class="badge ok">{{ user }}</span>
      </div>
      <button class="danger" @click="signOut">退出登录</button>
    </header>

    <nav class="tabs" style="margin-bottom: 16px">
      <button :aria-current="tab === 'overview'" @click="tab = 'overview'">概览</button>
      <button :aria-current="tab === 'hosts'" @click="tab = 'hosts'">主机清单</button>
      <button :aria-current="tab === 'snippets'" @click="tab = 'snippets'">片段清单</button>
    </nav>

    <OverviewView v-if="tab === 'overview'" />
    <HostsView v-else-if="tab === 'hosts'" />
    <SnippetsView v-else />

    <p class="muted small" style="margin-top: 24px">
      服务端只保存不透明信封，主机名、口令与私钥对它永远是密文；只有在服务端启用
      加密传输（通道密钥）后，它才读得出主机清单的元数据。
      无论是否启用，<strong>SSH 口令与私钥都不会出现在浏览器里</strong>：
      这个页面不接收、也不需要端到端口令。
    </p>
  </div>
</template>
