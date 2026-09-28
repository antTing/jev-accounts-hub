# jev-accounts-hub

TypeSafe / Jev 的多账户管理器和 API 网关。

把多个官方 TypeSafe 账户收进一个池子，统一鉴权、配额、用量和故障切换。下游继续用官方 System One 协议，只需要把 Base URL 指到本服务。

```text
调用方
  TYPESAFE_BASE_URL = http://127.0.0.1:8080
  TYPESAFE_API_KEY  = sk-jev-xxxxxxxx   ← 本服务签发的用户 Key
        │
        ▼
   jev-accounts-hub
   账户池 / 鉴权 / RPM / token 配额 / 429 换号
        │
        ▼
   api.typesafe.ai
   POST /v1/systemone
   GET  /v1/models
```

协议保持官方原样：`POST /v1/systemone`、`GET /v1/models`。不是 OpenAI `chat/completions` 兼容层。

## Features

- 多账户池：按权重轮询，429 / 529 / 5xx / 401 自动换号
- 出站代理池：HTTP / HTTPS / SOCKS5，账号可绑固定代理，不绑则从池轮询，池空才直连
- 用户 Key：RPM、token 配额、备注、过期与停用
- 上游 Key 落库 AES-256 加密，管理台只显示掩码
- 调用日志、用量统计、探活、试玩
- 原生 System One，官方 SDK 只改 `base_url`

## Requirements

任选一种运行方式：

- Docker Engine 24+ 和 Docker Compose
- Go 1.24+

另外需要：

- 能访问 `https://api.typesafe.ai`
- 至少一个 TypeSafe API Key（`jev_…` 或 `ts_…`），在 [TypeSafe](https://typesafe.ai) 控制台复制
- 空闲端口 `8080`（或自行修改 `JEVPROXY_LISTEN`）
- 可写的数据目录，默认 `./data`

多账户可以一起导入。Key 只存在服务端，管理台显示形如 `jev_****abcd`。

官方当前能力（以 TypeSafe 文档为准，可能会变）：

| 项         | 值                                        |
| ---------- | ----------------------------------------- |
| 模型       | `jev-latest`、`jev-preview`、`jev-1.13.0` |
| 计费       | 按 input tokens，output 免费              |
| 单账户限流 | 约 1200 RPM / 250k tokens/s               |
| 上下文     | 64k tokens                                |

## Quick Start

```bash
git clone https://github.com/<you>/jev-accounts-hub.git
cd jev-accounts-hub
docker compose up --build
```

或本地运行：

```bash
go run ./cmd/jevproxy
```

首次启动会在 `./data/` 生成：

| 文件          | 作用                                   |
| ------------- | -------------------------------------- |
| `admin.token` | 管理台口令                             |
| `master.key`  | AES-256 主密钥，用来加密落库的上游 Key |
| `jevproxy.db` | SQLite：账户、用户 Key、调用日志       |

打开 http://127.0.0.1:8080 注册登录。第一个注册的账号是管理员，之后注册的都是普通用户。`data/admin.token`（或 `JEVPROXY_ADMIN_TOKEN`）仍可应急进入，权限等同管理员。这不是 TypeSafe 的 `jev_` Key。

然后：

1. 导入 TypeSafe 账户：单条粘贴，或批量每行一个 `jev_…`（可写 `名称 jev_…`）
2. 点探活，确认账户能打到官方接口
3. 签发用户 Key：明文只显示一次，立刻复制
4. 打开试玩，用账户池打一发 System One
5. 把用户 Key 和网关 Base URL 发给调用方

生产请备份 `data/`，不要提交 git。这些文件已在 `.gitignore` 中排除。

## Usage

官方 Python SDK：

```python
from typesafe import TypeSafeClient, Noul

client = TypeSafeClient(
    api_key="sk-jev-你的用户Key",
    base_url="http://127.0.0.1:8080",
)
resp = client.system_one(
    state="Stripe linking has failed for days.",
    questions={"urgent": Noul("The note signals time pressure")},
)
print(resp.answers["urgent"].noul)
```

curl：

```bash
curl -s http://127.0.0.1:8080/v1/systemone \
  -H "Authorization: Bearer sk-jev-你的用户Key" \
  -H "Content-Type: application/json" \
  -d '{
    "state": "hello",
    "model": "jev-latest",
    "questions": {
      "ok": {"type": "noul", "instructions": "This is a greeting"}
    }
  }'
```

拉模型列表（官方结构，字段是 `models[].name`，不是 OpenAI 的 `data[].id`）：

```bash
curl -s http://127.0.0.1:8080/v1/models \
  -H "Authorization: Bearer sk-jev-你的用户Key"
```

请求里 `model` 可写：

| 名字          | 实际跑       |
| ------------- | ------------ |
| `jev-latest`  | `jev-1.13.0` |
| `jev-preview` | `jev-1.13.0` |
| `jev-1.13.0`  | 钉死这一版   |

## Admin UI

打开 http://127.0.0.1:8080 ，用账号登录。管理员看全部页面。普通用户只能看自己的用户 Key 和调用日志，并能自己创建 Key。

1 积分 = $1 调用额度。管理员在「账号积分」里给任意账号加减整数积分，也可以在「兑换积分」里按面额批量生成兑换码。用户在同一页输入兑换码，面额加进自己的余额。码只在生成时显示一次，用过即失效。普通用户余额大于 0 才能创建 Key；Key 只扣这个账号的积分，不限 token 配额，RPM 限制在 1–120。余额到 0 后，已有 Key 调用返回 402。调用按官方价 $42 / 十亿 input tokens 扣，output 免费。

应急口令是 `data/admin.token`（或 `JEVPROXY_ADMIN_TOKEN`），不是登录账号。用它进后台时没有积分余额，也不能兑换。它签发的用户 Key 不挂任何账号，调用不扣积分。

| 页       | 谁能看 | 做什么                                                         |
| -------- | ------ | -------------------------------------------------------------- |
| 上游 Key | 管理员 | 导入账户、批量导入、探活、停用、权重 / RPM、绑定出口代理       |
| 代理池   | 管理员 | 添加 / 批量导入 HTTP·SOCKS5 代理、探活（出口 IP / 国家）、启停 |
| 用户 Key | 都可看 | 管理员签发、备注、RPM / token 配额、清零用量；普通用户创建并删除自己的 Key。额度列是所属账号剩余积分 |
| 调用日志 | 都可看 | 按时间、成功/失败、错误关键字筛；管理员还可按用户、上游筛      |
| 试玩     | 都可看 | 用账户池直接打 `POST /v1/systemone`，成功后扣当前账号积分。应急口令不扣 |
| 兑换积分 | 都可看 | 用户兑换进自己的余额；管理员按面额生成兑换码                   |
| 账号积分 | 管理员 | 查看账号，按整数美元加减积分                                   |

上游出站走代理：账号可绑固定代理；不绑则从活跃池轮询；池空才直连。绑定代理不可用时**不会**回退直连（避免 IP 关联）。批量导入支持：

```text
socks5://user:pass@10.0.0.1:1080
http://1.2.3.4:8080
us-east socks5://10.0.0.2:1080
1.2.3.4:3128:user:pass
```

批量导入每行一条，支持空格、逗号，或 `----` 分隔：

```text
jev_xxxx
prod-1 jev_yyyy
name,ts_zzzz
user@example.com----apikey_xxxx----key_yyyy----auto
```

`----` 行里，邮箱当名称，只导入 `apikey_` / `jev_` / `ts_`。同行的 `key_`、`auto` 会忽略。重复 Key 会跳过。试玩会计入调用日志。登录账号的试玩按 input tokens 扣自己的积分；应急口令的试玩不扣，日志里 `user_key_id=0`。

## Rate limits

- 按上游返回的 `usage.input_tokens` 记账。output 官方免费，不向用户加收
- 用户 Key 可设 RPM 和 token 配额（`0` = 不限）。普通用户自建的 Key 配额固定为不限，额度看账号积分
- 上游账户可设权重、RPM；遇 429 / 529 / 5xx / 401 自动换号重试
- 用户 422（schema 错）原样返回，不换号空打

## Configuration

见 `.env.example`。常用：

```bash
JEVPROXY_LISTEN=:8080
JEVPROXY_DATA_DIR=./data
JEVPROXY_ADMIN_TOKEN=     # 留空则自动生成
JEVPROXY_MASTER_KEY=      # 64 位 hex，留空则自动生成
JEVPROXY_UPSTREAM=https://api.typesafe.ai
JEVPROXY_TIMEOUT=15s
```

## Codex / MCP Integration

This repository includes a small stdio MCP bridge at `cmd/jev-mcp`. The
user-level Codex MCP entry named `jev` exposes its `jev_decide` tool from any
project, so Codex can ask Jev for narrow typed judgments while keeping its
normal coding model and tool execution unchanged.

The bridge sends the native `POST /v1/systemone` request to the local gateway.
It reads `TYPESAFE_API_KEY` and `TYPESAFE_BASE_URL` from the process environment;
when those are absent, it falls back to `~/.codex/.env` (or the path in
`TYPESAFE_DOTENV`). No credentials are stored in this repository.

Start the gateway first, then open a new Codex task (or reopen an existing one)
so its MCP tool catalog is reloaded. The bridge is intentionally a decision
tool, not an OpenAI-compatible model provider.

## Community

QQ 群：`1102910606`

欢迎 Issue 和 PR。

## License

[MIT](LICENSE)
