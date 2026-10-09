---
name: commit
description: 本仓库的 Git 提交信息规范（Conventional Commits 风格，含类型与固定图标约定）
whenToUse: 当用户让我生成提交信息、提交代码、总结变更或整理 git 历史时
---

# Git 提交规范

本仓库采用 **Conventional Commits** 风格的提交信息，并为每种类型指定了固定图标。

## 提交格式

```
<icon> <type>(<scope>): <subject>
```

- `icon`: 提交类型图标（见下表）
- `type`：提交类型（见下表）
- `scope`（可选）：影响范围，如 `core`、`web`、`auth`、`user` 等
- `subject`：简短描述，使用中文或英文均可，但同一仓库建议统一

## 提交正文（Body）

非 trivial 的提交必须带正文：标题行后空一行，用 `- ` 无序列表逐条说明改动要点（每条一句话，说清"做了什么"而非复述标题）。琐碎改动（一两个文件的小修复）可只写标题。

模板：

```
<icon> <type>(<scope>): <subject>

- 改动要点 1
- 改动要点 2
- 改动要点 3
```

示例：

```
✨ feat(user): 新增用户导出功能与列表搜索优化

- 新增用户列表 Excel 导出接口，支持按搜索条件过滤
- 列表查询支持按部门与状态组合筛选
- 修复导出大数据量时的内存溢出问题
- 同步生成 gfa-web 前端 API 客户端代码
- 补充导出功能的单元测试
```

## 提交类型与图标

| 类型       | 图标 | 描述                                                        |
|------------|------|-------------------------------------------------------------|
| `init`     | 🎉   | 初始化项目                                                  |
| `feat`     | ✨   | 新功能                                                      |
| `fix`      | 🐞   | 错误修复                                                    |
| `docs`     | 📃   | 修改文档                                                    |
| `style`    | 🌈   | 格式修改（不影响功能，例如空格、分号等格式修正）            |
| `refactor` | 🦄   | 代码重构                                                    |
| `perf`     | 🎈   | 代码优化 / 性能优化                                         |
| `test`     | 🧪   | 新增测试 / 修改测试                                         |
| `build`    | 🔧   | 构建依赖更改                                                |
| `ci`       | 🐎   | 更改 CI 配置文件或者脚本                                    |
| `chore`    | 🐳   | 更改构建流程、或者增加依赖库、工具等                        |
| `revert`   | ↩    | 代码回退                                                    |

## 示例

```
🎉 init: initialize gfa-core project
✨ feat(auth): add JWT login
🐞 fix(user): correct pagination total count
📃 docs(readme): update local development guide
🌈 style(web): format tailwind class order
🦄 refactor(core): extract common middleware
🎈 perf(dao): add index for deleted_at filter
🧪 test(auth): add login unit tests
🔧 build(core): bump gf to v2.10.2
🐎 ci: add github actions workflow
🐳 chore: add commitlint config
↩ revert: revert "feat(auth): add JWT login"
```

## 注意事项

- 优先选择能准确表达改动意图的最小类型。
- 当一次改动同时包含多个类型时，建议拆分为多个提交；若必须合并，使用最主要的类型。
- 图标与类型之间保留一个空格，例如 `✨ feat(auth): ...`。

## 强制规则：提交前必须交互确认

**生成提交信息后，禁止直接执行 `git commit`**，必须先把提交信息完整展示给用户，并通过交互方式（`AskUserQuestion`）让用户确认，再按用户选择执行。选项至少包含：

- **确认提交**（按展示的信息提交）
- **拆分/调整**（如按路径拆成多个提交、或修改提交信息）
- **暂不提交**（仅展示信息，不落库）

只有在用户明确确认后才可执行提交；如需拆分多笔提交，拆分方案也应在同一轮交互中确认。若用户主动要求「直接提交、无需确认」，可按其指示执行一次，但不得据此省略后续轮次的确认。

其他约定：

- 暂存区为空时不要臆造提交信息：先说明「暂存区无内容」，并询问是否将工作区改动加入暂存区后再提交。
