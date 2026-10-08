<script setup lang="ts">
// Yank 的标记：一对终端括号 [ ]，中间一颗琥珀点（#104 换版）。
//
// 几何和 App 图标（tools/make-icon.swift）、菜单栏那枚（Sources/TermUI/BrandMark.swift）、
// public/brand.svg 是同一套两笔一圆。改一处要改四处 —— 门禁 Checks_Brand 会拿 BrandMark 的
// 常量算出下面这些数，逐条在这份文件里找，少一处就对不上账。
//
// 两个颜色都吃固定色（和品牌色同源），不吃 currentColor：这枚标记靠"青括号 + 中间那颗琥珀"
// 这一档冷暖对照成立，跟着主题变色就变成一坨单色剪影了。
withDefaults(defineProps<{ size?: number }>(), { size: 26 });
</script>

<template>
  <svg :width="size" :height="size" viewBox="0 0 100 100" aria-hidden="true"
       style="flex: none">
    <polyline points="36 26 25 26 25 74 36 74" fill="none" stroke="#5ac8a8" stroke-width="7.5"
              stroke-linecap="round" stroke-linejoin="round" />
    <polyline points="64 26 75 26 75 74 64 74" fill="none" stroke="#5ac8a8" stroke-width="7.5"
              stroke-linecap="round" stroke-linejoin="round" />
    <circle cx="50" cy="50" r="7.5" fill="#e6aa5a" />
  </svg>
</template>
