<script setup lang="ts">
// 通道密钥的配置入口。这一层以前两端各粘一把 64 个字符的十六进制/base64，还有一路来源是服务的
// 启动参数——于是"打开加密传输"要么改部署要么重启。现在只剩这一个入口、一种形状：自己定一句
// 短密码（至少 8 个字），Mac 的偏好设置里填同一句。
//
// 口径与 GET /api/channel 一致：这把密钥只进不出——服务端从不回传它，本页也只在按下保存的那一
// 瞬间持有用户刚敲进来的文本，成功后立刻清空输入框，于是 DOM 里、历史里、日志里都留不下副本。
// 输入框是遮罩式的（星号）：它现在是一句人能念出来的短密码，明文回显等于让别人瞥见就能用。
// 它也不是端到端那把：这里配的是让服务端解开外层信封读主机清单的传输层密钥，
// SSH 账号的口令与私钥仍在内层信封里，这个页面既读不到也不需要。
import { computed, onMounted, ref } from 'vue';
import type { ChannelState } from '../types';
import { ApiError, getChannelState, setChannelKey } from '../useApi';

const MIN_CHARS = 8;

const state = ref<ChannelState | null>(null);
const draft = ref('');
const busy = ref(false);
const error = ref('');
const notice = ref('');

const sourceLabel: Record<ChannelState['source'], string> = {
  page: '本页配置',
  none: '未启用',
};

// 按"字数"判断，中文一个字算一个：服务端那侧也是同一个口径。
const trimmed = computed(() => draft.value.trim());
const chars = computed(() => Array.from(trimmed.value).length);
const tooShort = computed(() => trimmed.value.length > 0 && chars.value < MIN_CHARS);

async function load() {
  error.value = '';
  try {
    state.value = await getChannelState();
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '读取加密传输状态失败，请稍后再试';
    state.value = null;
  }
}

async function save() {
  const value = trimmed.value;
  if (!value) {
    error.value = `请先填写通道密钥（自己定一句，至少 ${MIN_CHARS} 个字）`;
    return;
  }
  if (tooShort.value) {
    error.value = `太短了：现在 ${chars.value} 个字，至少 ${MIN_CHARS} 个字`;
    return;
  }
  error.value = '';
  notice.value = '';
  busy.value = true;
  try {
    state.value = await setChannelKey(value);
    notice.value =
      state.value.enabled && state.value.source === 'page'
        ? `已保存，服务端现在用这把密钥解开外层信封（指纹 ${state.value.fingerprint}）。`
        : '已保存。';
    draft.value = '';
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '保存失败';
  } finally {
    busy.value = false;
  }
}

async function clear() {
  if (
    !window.confirm(
      '清除后服务端将不再解开外层信封，历史里的信封会退回纯密文；主机清单不受影响。确定清除？',
    )
  )
    return;
  error.value = '';
  notice.value = '';
  busy.value = true;
  try {
    state.value = await setChannelKey('');
    notice.value = '已清除，加密传输关闭。';
    draft.value = '';
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '清除失败';
  } finally {
    busy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <section class="panel">
    <div class="row" style="justify-content: space-between">
      <h2>加密传输（通道密钥）</h2>
      <button :disabled="busy" @click="load">{{ busy ? '处理中…' : '重新读取' }}</button>
    </div>

    <div class="row">
      <span class="badge" :class="state && state.enabled ? 'ok' : 'bad'">
        {{ state ? sourceLabel[state.source] : '读取中…' }}
      </span>
      <span v-if="state && state.fingerprint" class="badge mono">指纹 {{ state.fingerprint }}</span>
    </div>

    <p class="muted small">
      这把密钥只管外层信封：启用后服务端才解得开客户端上传的信封内容，
      从而把<strong>同一批元数据</strong>按版本存进历史。
      主机清单那一页（名称、主机:端口、登录用户、认证方式、备注、堡垒机）走的是明文字段，
      <strong>不启用这里也照样能看到</strong>。
      这把密钥需要与 Mac 偏好设置里填的那句<strong>完全一致</strong>，
      两边的指纹核对得上才算配对成功；填错不会毁掉已有的清单，只是解不开新推上来的那一版。
    </p>

    <label class="field">
      <span>通道密钥（自己定一句，至少 8 个字）</span>
      <input
        v-model="draft"
        type="password"
        autocomplete="off"
        spellcheck="false"
        placeholder="输入短密码；保存后本页不再显示它"
        :disabled="busy"
        @keyup.enter="save"
      />
    </label>

    <p v-if="tooShort" class="msg-error small">还差 {{ MIN_CHARS - chars }} 个字（中文一个字算一个）。</p>

    <div class="row" style="margin-top: 8px">
      <button :disabled="busy || !trimmed || tooShort" @click="save">
        {{ busy ? '处理中…' : '保存密钥' }}
      </button>
      <button
        class="danger"
        :disabled="busy || !state || state.source !== 'page'"
        @click="clear"
      >
        清除本页配置
      </button>
    </div>

    <p v-if="notice" class="msg-ok small">{{ notice }}</p>
    <p v-if="error" class="msg-error" role="alert">{{ error }}</p>

    <p class="muted small">
      写在明处的代价：这把密钥会以本页填的原文存在服务端数据库的 settings 表里，
      谁拿到库文件谁就能解开外层信封——请把它当作与库文件同级的秘密来保护，
      并且把本页放在反代 + HTTPS 之后。服务端不直接拿它当密钥，而是先做 21 万轮单向派生，
      随机盐跟着信封一起上传，所以两端只填同一句话就够了。
      内层的 SSH 凭据不受影响，服务端和这个浏览器都解不开它们。
    </p>
  </section>
</template>
