# jev-hub

TypeSafe / Jev 的多账户管理器和 API 网关。

把多个官方 TypeSafe 账户收进一个池子，统一鉴权、配额、用量和故障切换。下游继续用官方 System One 协议，只需要把 Base URL 指到本服务。

```text
调用方
  TYPESAFE_BASE_URL = http://127.0.0.1:8080
  TYPESAFE_API_KEY  = sk-jev-xxxxxxxx   ← 本服务签发的用户 Key
        │
        ▼
   jev-hub
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

| 项 | 值 |
|---|---|
| 模型 | `jev-latest`、`jev-preview`、`jev-1.13.0` |
| 计费 | 按 input tokens，output 免费 |
| 单账户限流 | 约 1200 RPM / 250k tokens/s |
| 上下文 | 64k tokens |

## Quick Start

```bash
git clone https://github.com/<you>/jev-hub.git
cd jev-hub
docker compose up --build
```

或本地运行：

```bash
go run ./cmd/jevproxy
```

首次启动会在 `./data/` 生成：

| 文件 | 作用 |
|---|---|
| `admin.token` | 管理台口令 |
| `master.key` | AES-256 主密钥，用来加密落库的上游 Key |
| `jevproxy.db` | SQLite：账户、用户 Key、调用日志 |

打开 http://127.0.0.1:8080 ，把 `data/admin.token` 整行贴进登录框。这不是 TypeSafe 的 `jev_` Key。也可以用环境变量 `JEVPROXY_ADMIN_TOKEN` 自己指定。

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

| 名字 | 实际跑 |
|---|---|
| `jev-latest` | `jev-1.13.0` |
| `jev-preview` | `jev-1.13.0` |
| `jev-1.13.0` | 钉死这一版 |

## Admin UI

打开 http://127.0.0.1:8080 ，贴 `data/admin.token`。

| 页 | 做什么 |
|---|---|
| 上游 Key | 导入账户、批量导入、探活、停用、权重 / RPM |
| 用户 Key | 签发、备注、RPM / token 配额、清零用量 |
| 调用日志 | 按时间、成功/失败、用户、上游、错误关键字筛 |
| 试玩 | 用账户池直接打 `POST /v1/systemone`，不消耗用户配额 |

批量导入每行一条，支持空格、逗号，或 `----` 分隔：

```text
jev_xxxx
prod-1 jev_yyyy
name,ts_zzzz
user@example.com----apikey_xxxx----key_yyyy----auto
```

`----` 行里，邮箱当名称，只导入 `apikey_` / `jev_` / `ts_`。同行的 `key_`、`auto` 会忽略。重复 Key 会跳过。试玩会计入调用日志，`user_key_id=0`。

## Rate limits

- 按上游返回的 `usage.input_tokens` 记账。output 官方免费，不向用户加收
- 用户 Key 可设 RPM 和 token 配额（`0` = 不限）
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

## Community

QQ 群：`1102910606`

欢迎 Issue 和 PR。

## License

[MIT](LICENSE)
