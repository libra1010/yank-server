<script setup lang="ts">
// 修改「浏览器登录这个管理端」用的口令。
//
// 这一页同时管着两种口令，必须把话说死：这里改的只是网页登录口令。保护 SSH 凭据的
// 端到端口令既不进这个卡片、不进这个接口、也不进服务端数据库（SPEC §7），页面上没有
// 任何一个控件收它。
//
// 三个框都做成密码框，提交成功后立刻清空：口令只在点击那一次存在，不留在 DOM 里。
import { ref } from 'vue';
import { ApiError, changePassword } from '../useApi';

const MIN_LEN = 10;

const oldPassword = ref('');
const newPassword = ref('');
const confirmPassword = ref('');
const busy = ref(false);
const error = ref('');
const notice = ref('');

function check(): string {
  if (!oldPassword.value || !newPassword.value || !confirmPassword.value) {
    return '原口令、新口令、确认新口令都要填';
  }
  if ([...newPassword.value].length < MIN_LEN) {
    return `新口令至少需要 ${MIN_LEN} 个字符`;
  }
  if (newPassword.value === oldPassword.value) {
    return '新口令不能和原口令一样';
  }
  if (newPassword.value !== confirmPassword.value) {
    return '两次输入的新口令不一致';
  }
  return '';
}

async function submit() {
  error.value = '';
  notice.value = '';
  const reason = check();
  if (reason) {
    error.value = reason;
    return;
  }
  busy.value = true;
  try {
    const res = await changePassword(oldPassword.value, newPassword.value);
    notice.value = res.reason || '登录口令已修改。';
    oldPassword.value = '';
    newPassword.value = '';
    confirmPassword.value = '';
  } catch (e) {
    // 服务端的中文原因原样转达，不覆盖成通用文案。
    error.value = e instanceof ApiError ? e.message : '修改失败，请稍后再试';
  } finally {
    busy.value = false;
  }
}

function reset() {
  oldPassword.value = '';
  newPassword.value = '';
  confirmPassword.value = '';
  error.value = '';
  notice.value = '';
}
</script>

<template>
  <section class="panel">
    <div class="row" style="justify-content: space-between">
      <h2>登录口令（管理端）</h2>
      <button :disabled="busy" @click="reset">清空</button>
    </div>

    <p class="muted small">
      这里改的是<strong>用浏览器打开这个管理页面时的登录口令</strong>，
      与保护 SSH 账号凭据的端到端口令<strong>没有关系</strong>：
      那把口令只存在你的 Mac 上，永远不会进到这一页、这个接口或这个数据库。
    </p>

    <label class="field">
      <span>原口令</span>
      <input
        v-model="oldPassword"
        type="password"
        autocomplete="current-password"
        :disabled="busy"
        @keyup.enter="submit"
      />
    </label>
    <label class="field">
      <span>新口令（至少 10 个字符）</span>
      <input
        v-model="newPassword"
        type="password"
        autocomplete="new-password"
        :disabled="busy"
        @keyup.enter="submit"
      />
    </label>
    <label class="field">
      <span>确认新口令</span>
      <input
        v-model="confirmPassword"
        type="password"
        autocomplete="new-password"
        :disabled="busy"
        @keyup.enter="submit"
      />
    </label>

    <div class="row" style="margin-top: 8px">
      <button :disabled="busy" @click="submit">{{ busy ? '提交中…' : '修改登录口令' }}</button>
    </div>

    <p v-if="notice" class="msg-ok small">{{ notice }}</p>
    <p v-if="error" class="msg-error" role="alert">{{ error }}</p>

    <p class="muted small">
      改完之后的影响写在明处：这个账号在<strong>其他浏览器上的会话会被退出</strong>，
      需要拿新口令重新登录；当前这个页面不用重新登录。
      Mac 终端的同步<strong>不受影响</strong>——设备配对令牌与网页口令是两回事。
    </p>
  </section>
</template>
