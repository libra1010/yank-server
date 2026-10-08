<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue';
import { ApiError, createPairCode } from '../useApi';

const code = ref('');
const note = ref('');
const secondsLeft = ref(0);
const busy = ref(false);
const error = ref('');
let ticker: ReturnType<typeof setInterval> | undefined;

function stopCountdown() {
  if (ticker !== undefined) clearInterval(ticker);
  ticker = undefined;
}

async function generate() {
  stopCountdown();
  error.value = '';
  code.value = '';
  note.value = '';
  secondsLeft.value = 0;
  busy.value = true;
  try {
    const result = await createPairCode();
    code.value = result.code;
    note.value = result.note;
    secondsLeft.value = result.expiresIn;
    ticker = setInterval(() => {
      secondsLeft.value -= 1;
      if (secondsLeft.value <= 0) {
        stopCountdown();
        code.value = '';
        note.value = '';
      }
    }, 1000);
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '生成配对码失败';
  } finally {
    busy.value = false;
  }
}

// 离开视图就停表，别留一个会改写状态的计时器。
onBeforeUnmount(stopCountdown);
</script>

<template>
  <section class="panel">
    <h2>配对新的 Mac</h2>
    <p class="muted small">
      在 Mac 端「偏好设置 › 同步」里选「用配对码连接」，把下面这串码输进去。
      配对码五分钟内有效、只能用一次；换到的设备令牌才有写入权限。
    </p>
    <div class="stack">
      <button class="primary" :disabled="busy" @click="generate">
        {{ busy ? '生成中…' : code ? '重新生成配对码' : '生成配对码' }}
      </button>
      <template v-if="code">
        <p class="code-display">{{ code }}</p>
        <p class="row" style="justify-content: center">
          <span class="badge warn">剩余 {{ secondsLeft }} 秒</span>
        </p>
        <p v-if="note" class="muted small" style="text-align: center">{{ note }}</p>
      </template>
      <p v-if="error" class="msg-error" role="alert">{{ error }}</p>
    </div>
  </section>
</template>
