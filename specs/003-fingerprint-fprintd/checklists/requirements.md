# Specification Quality Checklist: 基于 fprintd 的本地指纹识别认证

**Purpose**: Validate specification completeness and quality before planning / 实现  
**Created**: 2026-09-04  
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No unnecessary low-level API dumps in spec.md（D-Bus 细节在 contracts/research）
- [x] Focused on user value and business needs
- [x] Written for stakeholders + 实现对照
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain（残留 open point 仅在 research D5）
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Acceptance scenarios defined（录入 / 识别 / 管理 / CLI 对照 / 可切换）
- [x] Edge cases identified（含 Polkit、双源、旧数据清理）
- [x] Scope clearly bounded（唯一 fprintd 路径；移除旧 libfprint 插件；CLI 非热路径）
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] Functional requirements map to拟议行为（含 FR-018 替换/不保留旧实现）
- [x] User scenarios cover primary flows
- [x] Contracts / data-model / quickstart / tasks 已齐套
- [x] 原 `002-fingerprint-recognition` 规格目录**保留**作对照；本目录为新交付规格；实现期只删 libfprint 插件代码

## Notes

- 本文档为 **Draft**：fprintd 替换路径尚未实现
- 产品决策：003 **替换**旧 libfprint 直连**实现代码**；002 规格文档保留；不保留双后端运行
- 检查通过后可按 tasks.md 开工（先删旧插件代码再接 fprintd）
