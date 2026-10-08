<script setup lang="ts">
// 片段清单**读失败**时的说明（网络、权限、服务端故障），体例照 HostsNotice.vue。
// 规则不变：绝不提供「把端到端口令输到网页里」这类入口。
defineProps<{ reason?: string }>();
</script>

<template>
  <div class="stack">
    <p v-if="reason" class="msg-error" role="alert">服务端答复：{{ reason }}</p>
    <p class="muted small">
      这里能看到片段的<strong>名称、分组、正文与参数</strong>。
      <strong>口令本体与私钥永远只在端到端信封里，服务端和浏览器都读不到</strong>——
      疑似含口令的正文在 Mac 上就被整句隐去，所以那一格出现的中文提示就是它的全部，
      这一页不判断、不打码，也任何时候都不需要你把口令输进网页。
    </p>
  </div>
</template>
