# 🤖 QQBotAgent · QQ 机器人助手

> 一个**纯聊天**的 QQ AI 机器人：接入大模型，走官方 QQBot API。无技能、不常驻提示词，token 只花在聊天上。
> A **chat-only** QQ AI bot: LLM-powered, built on the official QQBot API, no skills, no resident prompts — tokens spent on chatting, nothing else.

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Release](https://img.shields.io/github/v/release/dryin123/QQBotAgent?label=Release&color=009688)](https://github.com/dryin123/QQBotAgent/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/dryin123/QQBotAgent/ci.yml?label=CI)](https://github.com/dryin123/QQBotAgent/actions)
[![License](https://img.shields.io/badge/License-MIT__Personal_Use-009688.svg)](LICENSE)

---

## 📦 版本记录

| 版本 | 日期 | 说明 |
|---|---|---|
| [v3.0.0](https://github.com/dryin123/QQBotAgent/releases/tag/v3.0.0) | 2026-09-05 | 修复启动校验、WebSocket 断线自动重连、密钥存储加固等（详见 Release 说明） |
| [v2.0.0](https://github.com/dryin123/QQBotAgent/releases/tag/v2.0.0) | 2026-09-02 | 多轮修复与优化版（token 估算、压缩后台化、压缩算法重写、日志脱敏、/health、CI/Docker/单测等） |
| [v1.0.0](https://github.com/dryin123/QQBotAgent/releases/tag/v1.0.0) | 2026-09-01 | 初版·纯聊天 QQ 机器人 |

完整改动见 [Commits](https://github.com/dryin123/QQBotAgent/commits/main)。

---

## 🎯 为什么做 · Why

很多人只是想给 QQ 机器人陪聊，却被迫接入完整 agent 框架：常驻大段 prompt、技能（skills）、工具定义——大部分从不用于聊天，却每轮都占 token，成本高。

本项目只做一件事：**聊天**。不要 agent 框架，不要常驻技能与提示词。

| 常见方案痛点 · Pain point | 本项目做法 · This project |
|---|---|
| 传统 QQBot 需登录 QQ 号，回复死板，易触发封号 | 走**官方 QQBot API**，接入 LLM 智能回复，无需登录个人号 |
| agent 框架常驻 prompt/skills，token 消耗高 | **纯聊天**，无技能、无常驻提示词，token 消耗低 |
| 上下文越长费用越高 | **上下文压缩**：按组压缩、摘要本地缓存、达上限迭代再压缩 |

---

## ✨ 特性 · Features

- 💬 **纯聊天，无技能**：没有多余的 skills/prompt 占 token
- 🧠 **接入 LLM**：支持 DeepSeek / GLM / Kimi / Ollama 等（OpenAI 兼容端点可自定义）
- 📉 **上下文压缩**：对话按组分片，超限压成摘要**保存在本地**并复用；再次打满**迭代再压缩**，控制 token
- 🔄 **分组翻篇可调**：超过设定轮数自动开启新对话组，上下文隔离
- 🗄 **历史本地持久化**：聊天记录存本地，随时查看、按需调用
- 🔐 **密钥本地加密**：凭证 Windows DPAPI 加密存储，界面掩码显示，敏感内容发送前过滤
- 🌐 **Web 管理界面**：配置、人设、对话记录、Token 统计，可视化操作

---

## ⚖️ 与其他方案对比 · What's Different

| | 传统 QQBot | agent 框架 + QQBot | 本项目 |
|---|---|---|---|
| 登录方式 | 个人 QQ 号 | 个人号 / 官方 API | 官方 API |
| 常驻 skills/prompt | 否 | 是（token 高） | **否** |
| 聊天智能度 | 关键词 / 死板 | 智能 | 智能 |
| 上下文成本控制 | 无 | 弱 | 按组压缩 + 本地摘要复用 |
| 定位 | 自动化脚本 | 多能力 agent | **纯聊天** |

---

## 🚀 快速开始 · Quick Start

```bash
pip install -r requirements.txt
python app.py        # 启动后访问 http://127.0.0.1:8000 配置
```

在 Web 界面填写：QQ 机器人 AppID / AppSecret（[QQ 开放平台](https://q.qq.com/) 获取）、大模型 Provider 与 API Key、人设、分组轮数、思考深度。

打包（可选）：

```bash
pyinstaller --noconfirm --onedir --windowed --name QQBotAgent app.py
```

---

## 🗂 目录结构 · Structure

```
QQBotAgent/
├── app.py                 # 主程序（单文件）
├── requirements.txt
├── .gitignore
├── LICENSE
├── config.example.json    # 配置示例（占位符）
├── Dockerfile             # 容器化部署（可选）
├── .github/workflows/ci.yml  # CI：编译 + import + 单测
├── docs/compression.md    # 上下文压缩算法说明
├── tests/test_core.py     # 核心纯函数单测（python -m unittest discover -s tests）
└── data/                  # 运行时生成，已被 .gitignore 排除
    ├── config.json        #   配置（密钥本地加密保存）
    ├── sessions.json      #   历史聊天记录
    ├── users.json         #   群成员库
    ├── token_usage.json   #   Token 消耗统计
    └── app.log            #   运行日志（自动轮转）
```

---

## 🔄 升级注意 · Upgrade Notes

- **v2.0.0（2026-09-02）**：上下文压缩改为后台执行（不再阻塞回复）；Token 估算改为中英混合加权（阈值判断更贴近真实用量，压缩触发点可能比旧版更早/更晚，属预期）；`--stop` 的端口清理只终止本程序进程，不再误杀其他占用 8000 的程序；Web 状态栏每 5 秒自动刷新；新增 `/health` 健康检查端点；日志写入 `data/app.log`（自动轮转 + 敏感信息脱敏）。压缩算法细节见 [docs/compression.md](docs/compression.md)。
- 配置与数据格式不变，旧 `config.json` / `sessions.json` / `token_usage.json` 可直接沿用，无需迁移。

---

## 🔐 安全说明 · Security

- **密钥加密存储**：API Key / AppSecret 用 Windows DPAPI 加密后存于本地 `data/config.json`，界面掩码显示，不显示明文。
- **仅监听本机**：Web 界面绑定 `127.0.0.1`，接口带来源校验，非本机来源的请求会被拒绝。
- **日志脱敏**：运行日志自动打码 `sk-` / Bearer / 密钥类字段，且自动轮转防止膨胀。
- **仓库不含凭证**：`data/`、`aux_data/`、`config.json` 等敏感路径已被 `.gitignore` 排除，提交内容不包含任何真实密钥与聊天记录。
- **建议**：源码完全公开，部署与使用前请自行审查代码、评估风险；请勿将真实凭证发给任何人。

---

## ⚠️ 免责声明 · Disclaimer

> **本项目仅供学习研究。** 软件按现状（AS-IS）提供，不提供任何明示或暗示的担保，不保证可靠性、安全性、稳定性或无缺陷，请勿直接用于生产环境。源码完全公开，使用前请自行审查代码、自行评估安全风险。因使用、配置、修改或部署本项目产生的任何直接或间接损失（包括但不限于数据丢失、账号异常），作者不承担任何责任；使用本项目的全部风险由使用者自行承担，使用即视为同意自行承担全部责任。使用者自行修改或二次分发本项目所产生的后果与本项目无关。作者不提供技术支持、缺陷修复或版本更新义务。所有回复内容由第三方大模型生成，作者不对其准确性或合法性负责。
>
> **仅限个人使用与个人数据存储，禁止任何形式的商业使用。**
>
> 完整条款以 [LICENSE](LICENSE) 为准。

<details>
<summary>English · Disclaimer (click to expand)</summary>

> **This project is for learning and research only.** The software is provided "AS-IS" without warranty of any kind, express or implied, including but not limited to reliability, safety, stability, or fitness for a particular purpose. Do not use it in production. The source code is fully open; please review the code and assess security risks yourself before use. The author shall not be liable for any direct or indirect loss (including but not limited to data loss or account issues) arising from the use, configuration, modification, or deployment of this project. All risk arising from the use of this project is borne by the user; by using it, you agree to bear all responsibility yourself. Consequences of any user-modified or re-distributed version are unrelated to this project. The author has no obligation to provide technical support, defect fixes, or version updates. All replies are generated by third-party LLMs; the author is not responsible for their accuracy or legality.
>
> **For personal use and personal data storage ONLY. Any commercial use is strictly prohibited.**
>
> The full terms are governed by [LICENSE](LICENSE).

</details>

---

## 📄 许可证 · License

**MIT License with Personal-Use & Non-Commercial Additional Terms**：基于 MIT（OSI 标准开源许可），附加「个人使用 / 非商业」条款与免责条款。允许个人使用 / 修改 / 私人部署；**禁止任何形式的商业使用**（出售、转售、商业部署、付费服务、营利性运营）。软件按现状提供，不作任何明示或暗示的担保，作者不承担任何责任。详见 [LICENSE](LICENSE)。

> **商标声明**："QQ" 与 "QQBot" 为腾讯公司的注册商标。本项目为个人作品，**非腾讯官方项目**，与腾讯及其关联公司**无任何关联、赞助、背书或合作关系**。本项目使用腾讯公开的 QQ 机器人 OpenAPI，但不对腾讯做出任何承诺或保证。
>
> **Trademark Notice**: "QQ" and "QQBot" are registered trademarks of Tencent. This project is a personal work, **NOT an official Tencent project**, and has **no affiliation, sponsorship, endorsement, or partnership** with Tencent. This project uses Tencent's public QQ Bot OpenAPI but makes no warranties regarding Tencent.
