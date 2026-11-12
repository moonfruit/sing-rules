# sing-rules

Based on [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)

订阅配置 `config/config.json` 中的 `natural_selection` 声明该订阅参与的自然选择分组，
可选值为 `AI`、`Claude`、`ChatGPT`，省略时不参与这三个分组。目前仅 Ash 配置了
`"natural_selection": ["AI", "Claude", "ChatGPT"]`。
Claude 仍仅使用美国节点，AI 和 ChatGPT 仍仅使用美国和日本节点；手动选择不受此字段影响。

## 节点出口情况表

`probe-exits.py` 将出口采集和 IP 信息查询分开执行，不启动独立 sing-box。
数据库以**完整节点名称**为主键，用于后续按节点筛选；相同名称视为同一节点，改名则新增记录。
脚本不会自动剔除节点或修改规则。

```bash
# API 有认证时设置 CLASH_API_SECRET；ipapi.is 的 Key 设置在 IPAPI_IS_KEY。
# 请在自己的 shell 中配置，脚本不会从项目配置里读取或保存凭证。

# 1. 从本地 Clash API 展开指定 selector/urltest 组，依次采集节点出口。
venv/bin/python probe-exits.py collect \
  --group '🤖 AI' --group '🤖 ChatGPT' \
  --database data/exits.sops.json

# 2. 独立查询出口 IP 信息，默认仅补齐缺失的来源；此处由外部包装命令选择 7898 入口。
proxy global venv/bin/python probe-exits.py enrich

# 需要更新旧 IP 信息时显式刷新；失败保留上次成功结果。
proxy global venv/bin/python probe-exits.py enrich --refresh

# 3. 导出按节点、探测服务排列的 CSV，重复行表示同一节点的不同服务观测。
venv/bin/python probe-exits.py export \
  --output reports/exits.csv
```

默认数据库是仓库内的 `data/exits.sops.json`。脚本直接读写 SOPS binary 密文，
节点名称、IP 等 JSON 键名也整体隐藏，解密后的数据只在内存中流转，不生成临时明文。
需安装 `sops` 并配置仓库现有 age 接收者对应的解密密钥；`.sops.yaml` 复用 `config/secrets.env` 的接收者。
SOPS 失败会报错，不会回退到明文或覆盖旧库；内容未变化时保持原密文，避免无意义的 Git 差异。
显式指定普通 `.json` 路径时仍支持旧明文格式，`.sops.json` 路径则强制使用整体加密格式。

日常更新先拉取最新密文，然后运行 `collect`/`enrich`，最后提交 `data/exits.sops.json` 的变更。
两阶段均在锁内增量合并并原子保存，未探测到的节点和旧历史继续保留。
不要直接解决密文文本冲突：多机器并发修改时应先解密双方数据并按节点、观测时间合并，再重新加密。
本次迁移后原 `reports/exits.json` 保留为本地明文备份，不再是默认库。

数据库读写由 `common.exit_report` 统一管理，不依赖网络或代理。
未来 `clash-to-sing.py` 等消费者可只读导入，无需自行执行 SOPS，也不会触发探测或更新：

```python
from common.exit_report import load_database

database = load_database()  # 默认读取 data/exits.sops.json，也可以显式指定路径
node = database['nodes'].get(node_name)
```

目前未把数据库过滤逻辑接入配置生成器；解密失败会抛出异常，由调用者决定如何处理。

采集默认使用 `http://127.0.0.1:9999` 的 Clash API、`http://127.0.0.1:7898` 的 HTTP/mixed 代理。
使用 `--api`、`--proxy` 修改地址；代理入口必须属于该 API 控制的同一个 sing-box 实例。
分组从运行中的 `/proxies` 读取，`--group` 按组名包含的关键词匹配，区分大小写，可重复指定。
例如 `--group ABC` 会选择 `ABC`、`机场 ABC 自动` 等所有名称包含 `ABC` 的 selector/urltest 组；
多个关键词取并集，不匹配普通节点名称。匹配后的完整组名会打印出来，嵌套组递归展开、节点去重。
即使某个组名与关键词完全相同，也会同时选中其它包含该关键词的组；空关键词或任一关键词无匹配时报错。
`GLOBAL` 必须能直接选择所有待测节点，否则在切换前报错。

采集期间会暂时切换为 global 模式并逐个选择 GLOBAL 出口，**会影响同一代理实例的其它新建连接**。
结束、异常、Ctrl-C 或 SIGTERM 时会尝试恢复原模式和 GLOBAL 选择；恢复失败会显式报错。
脚本不主动关闭既有连接。采集时请勿同时操作该实例的模式/节点，也不要用不同数据库并行采集。
进程被强制杀死或断电时不能保证恢复。

默认通过 `https://api.ipify.org?format=json` 和 `https://api.myip.com` 获取出口；
可重复传入 `--echo-url` 替换，接口需返回含 `ip` 的 JSON 或纯文本 IP。
每次请求使用独立连接并通过请求参数指定本地代理，保留 requests 默认的环境配置读取行为。
每个服务的观测独立保存；实际获取的是该服务请求所用的 IPv4 或 IPv6，
不保证覆盖双栈，也不据此推断未观测地址族不可用。按目标分流、多出口或轮换 IP 会产生不同结果。

信息查询使用两个来源：

- [ip-api.com](https://ip-api.com/docs/api:batch)：免 Key，包含地区、ISP、ASN、hosting、proxy、mobile。
  使用 HTTP POST `/batch`，每批最多 100 个 IP，免费批量接口每源 IP 每分钟 15 次请求，仅限非商业用途；
  脚本控制批次间隔并读取 `X-Rl`/`X-Ttl`。
- [ipapi.is](https://ipapi.is/developers.html)：使用环境变量 `IPAPI_IS_KEY`，通过 HTTPS POST 发送 Key。
  使用 `ips` 数组批量查询，每批最多 100 个 IP；免费账户每天 1,000 次查询，批次中的每个 IP 各消耗一次额度。
  不设置 Key 时明确提示并跳过该来源，不使用匿名缩减版。

`enrich` 的代理完全由外部环境决定，遵循 requests 的环境配置（包括 `HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY`），
不提供内部代理参数。可以使用 `proxy ./probe-exits.py enrich`（默认入口 7890）或
`proxy global ./probe-exits.py enrich`（入口 7898）。此阶段不会切换节点、GLOBAL 或代理模式。
也可用 `enrich --ip 8.8.8.8` 补充查询指定公网 IP，只更新内部 IP 缓存，不创建虚拟节点。
请求超时可通过 `--timeout` 调整。数据库响应的 IP 必须与查询 IP 一致才接受。

查询按 IP/来源复用结果，因此多个节点共用出口不会重复消耗额度。
每个来源只查询缺失的 IP（`--refresh` 除外），去重后自动按最多 100 个一批发送，
按响应中的 IP 逐项校验与合并，批次内单项失败不影响其它成功结果。
遇到 HTTP 429/403 或 ip-api 的剩余额度归零时，会记录冷却时间到 `provider_limits`，
冷却期间暂停该来源，继续处理另一来源；冷却信息跨运行保留，不长时间阻塞等待。
`--refresh` 也遵守冷却时间。需要在额度恢复后重新运行命令补齐未完成项。

数据库结构：

```text
schema_version: 1
nodes:
  <完整节点名称>:
    groups: 所属的已选组（增量合并）
    first_seen / last_seen: 首次及最近采集时间
    current: 按探测服务保存最近成功的出口 IP、地址族、观测时间
    last_attempts: 按服务保存最近尝试的状态、时间和错误
    observations: 历次成功和失败观测
    summary: 当前出口各自的汇总、来源意见与冲突
ip_cache:
  <IP>:
    sources:
      <来源>: 原始 data、queried_at、last_attempt、最近 error
provider_limits: 各来源的冷却截止时间（Unix 时间戳）及原因
```

所有时间使用 UTC。旧节点、旧出口观测、旧 IP 缓存和其它来源都不会因本次未出现而删除。
失败不覆盖上次成功出口或来源数据；`last_attempts`/`error` 可用于识别本次失败及过期结果。
节点换 IP 后，汇总只取各服务当前 IP 的数据，不把旧 IP 的属性移植给新 IP。
每次完成一次观测或一批 IP 查询即原子落盘，同一数据库写入互斥；损坏或不支持的数据库版本会报错，不会重建覆盖。
只有整体加密的 `data/exits.sops.json` 入库；明文备份和 CSV 放在被 `.gitignore` 忽略的 `reports/`。

汇总字段的 `value` 是来源一致时的值，`sources` 保存各来源意见，分歧时 `conflict=true`、`value=null`。
没有数据是未知，不是 false；CSV 使用 `unknown`、`conflict` 表示，保留探测错误和查询错误。
CSV 同时提供国家代码、地区、城市、ISP、组织、ASN、hosting、proxy、VPN、Tor、mobile 和网络类型。
`probe_attempted_at` 为最近探测时间，`query_times` 保存每个来源的成功查询及最近尝试时间。
`proxy` 表示数据库是否识别为代理/VPN/Tor，不表示节点本身是否具备代理功能；
ipapi.is 的 proxy 汇总为其 `is_proxy`/`is_vpn`/`is_tor` 的组合判断。

**ISP 网络不等于家宽，非机房也不等于家宽。** 当前来源不足以可靠确认家宽，
`residential` 保持未知，并保留 `network_type`、`asn_type` 等证据供人工判断。
机房与代理属性分别处理，不生成缺乏依据的统一“好坏分数”。

退出码：`0` 全部完成（已有缓存也算完成），`1` 存在失败、限流跳过或输入错误，`130` 用户中断。
模拟测试不需要真实代理或 Key：`venv/bin/python -m unittest discover -s tests -v`。
