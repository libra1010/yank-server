<script setup lang="ts">
import { ref } from 'vue';
import { ApiError, login, register } from '../useApi';
import BrandMark from './BrandMark.vue';

const mode = ref<'login' | 'register'>('login');
const name = ref('');
const password = ref('');
const busy = ref(false);
const error = ref('');

// 注册用的密码是「登录这个管理端」的密码，和 Mac 上的同步口令完全是两回事。
async function submit() {
  error.value = '';
  if (name.value.trim() === '' || password.value === '') {
    error.value = '请填写账号名和密码';
    return;
  }
  if (mode.value === 'register' && password.value.length < 10) {
    error.value = '管理端密码至少 10 个字符';
    return;
  }
  busy.value = true;
  try {
    if (mode.value === 'register') {
      await register(name.value.trim(), password.value);
      // 账号刚建好还没有会话令牌，立刻用同一份凭据换一次登录。
      await login(name.value.trim(), password.value);
    } else {
      await login(name.value.trim(), password.value);
    }
    password.value = '';
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '登录失败，请稍后再试';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="panel" style="max-width: 460px; margin: 8vh auto">
    <h1 class="brand" style="margin-bottom: 12px"><BrandMark :size="28" /> Yank 同步管理端</h1>
    <p class="muted small">
      这里只存不透明密文。口令与私钥在服务端、也在这个浏览器里都永远不可见；
      管理端只做元数据展示与版本管理，不接收端到端口令。
    </p>

    <div class="tabs" style="margin: 14px 0">
      <button :aria-current="mode === 'login'" @click="mode = 'login'">登录</button>
      <button :aria-current="mode === 'register'" @click="mode = 'register'">注册</button>
    </div>

    <form class="stack" @submit.prevent="submit">
      <label class="field">
        <span>账号名</span>
        <input v-model="name" autocomplete="username" placeholder="3–64 个字符" />
      </label>
      <label class="field">
        <span>管理端密码</span>
        <input
          v-model="password"
          type="password"
          autocomplete="current-password"
          :placeholder="mode === 'register' ? '至少 10 个字符' : ''"
        />
      </label>
      <button class="primary" type="submit" :disabled="busy">
        {{ busy ? '处理中…' : mode === 'register' ? '注册并登录' : '登录' }}
      </button>
      <p v-if="error" class="msg-error" role="alert">{{ error }}</p>
    </form>

    <p class="muted small" style="margin-top: 14px">
      账号在这里创建；<strong>同步口令在 Mac 端的「偏好设置 › 同步」里设置</strong>，
      两者不是同一个东西，这个页面任何时候都不需要你输入同步口令。
      管理端密码丢了可以在这里重新注册；
      <strong>同步口令丢了，服务端那份密文谁也无法打开</strong>，只能删除重来。
    </p>
  </div>
</template>
