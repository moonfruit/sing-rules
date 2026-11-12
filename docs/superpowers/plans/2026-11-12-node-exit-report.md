# 节点出口情况表实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 按本地代理组采集节点出口，按节点名称增量维护情况表，为后续人工筛选或规则剔除提供依据。

**Architecture:** `probe-exits.py` 提供 `collect`、`enrich`、`export` 三个独立子命令。节点数据库以节点名称为主键；出口观测和 IP 数据库查询分离，IP 仅作为内部查询缓存的键。通过现有 Clash API 和 HTTP 代理采集，不启动独立 sing-box。

**Tech Stack:** 项目 venv、Python 标准库、现有 requests；不增加依赖。

**Spec:** 本文“行为约定”及本次对话中用户的修订。

## 行为约定

- `collect --group KEYWORD` 可重复指定，按 API 的组名做区分大小写的包含匹配（用户后续修订），选择所有匹配的 selector/urltest 组并取并集。匹配组名打印到标准错误；空关键词或任一关键词无匹配时报错。递归展开、节点去重，检测组循环、缺失引用，排除 DIRECT/REJECT 等非代理出口。
- 默认 API 为 `http://127.0.0.1:9999`，代理为 `http://127.0.0.1:7898`；允许覆盖。API secret 从环境变量读取，不写入结果。
- 参考 `env/bin/test-proxy-sing`，通过 GLOBAL 逐个切换实际节点，并经显式 HTTP 代理发出探测请求。切换前保存模式与 GLOBAL 选择，确保探测走 global 模式，正常、异常及 Ctrl-C 退出均尝试恢复；恢复失败必须显式报错。
- 切换影响本地其它新建连接，采集不并行切换，不主动断开用户既有连接；每个探测请求使用新连接。切换前验证所有待探测节点均可从 GLOBAL 选择。
- 出口服务使用免 Key 的 HTTPS IP 回显接口，保存服务 URL、实际 IP、地址族与时间；使用多个服务时保留不同出口，不能把双栈或按目标分流造成的不同 IP 合并成同一个 IP。采集的地址族只是实际观测，不声称证明另一地址族不可用。
- `enrich` 不切换节点，按当前观测的去重 IP 查询 ip-api.com 和 ipapi.is；按来源筛选缺失项，每批最多 100 个 IP。ip-api 使用 `/batch`（15 请求/分钟），ipapi.is 使用带 `ips` 的 POST，仍按各 IP 消耗额度。后者使用 `IPAPI_IS_KEY`，不使用 ipwho.is。无 Key 时明确跳过 ipapi.is 并提示，不静默使用缩减版接口。
- 遵守 ip-api 的 X-Rl/X-Ttl 和数据库的 Retry-After；额度耗尽后暂停该来源，不继续轰炸。Key 不进入日志、错误文本、结果或缓存，ipapi.is 用 POST JSON 传 Key。
- 节点库顶层含 schema_version、nodes、ip_cache；`nodes` 以完整节点名为键，包含 groups、first_seen、last_seen、last_attempt、observations、当前出口及汇总。相同名称视为同一节点；名称变化视为新节点。
- 成功采集更新当前出口并追加历史观测；不同服务的当前出口分别维护。探测失败记录失败时间与原因，保留上次成功观测并明确标记其时效，不假装是本次成功。
- 仅新增和更新，不删除未出现在本次组内的旧节点、旧 IP、历史和来源；节点换 IP 后不沿用旧 IP 的属性作为新 IP 的结论。
- 按 IP/来源缓存成功查询结果，默认补缺失，`enrich --refresh` 显式刷新。成功结果带查询时间；失败仅更新错误信息，不覆盖已有成功结果。
- 汇总包括国家、地区、城市、ISP、组织、ASN、机房、代理/VPN/Tor、移动网络、家宽证据。保留各来源值及冲突；缺失值不是 false。代理库标记表示被数据库识别，不代表“该节点是否用作代理”的功能判断。
- ISP 类型只证明 ISP 网络，不能直接等同家宽；缺少住宅网络证据时家宽为未知。不同属性独立判断，家宽和代理可以同时为是。
- 按节点导出表格，包含当前出口、观测/查询时间、错误和冲突，供人工筛选；不自动剔除或改动现有规则。
- JSON 数据库采用原子替换写入；损坏或不支持版本的旧库报错，不能静默重建覆盖；采集逐项、查询逐批落盘，避免中断丢失已完成工作。同一数据库的写操作互斥，避免并发覆盖。

## 文件职责

- `probe-exits.py`：参数解析与三个子命令。
- `common/exit_report.py`：节点库加载、互斥与原子保存、增量更新和汇总。
- `common/exit_probe.py`：Clash API、组展开、状态恢复和出口采集。
- `common/ip_info.py`：两个数据库适配、限流、IP 校验和字段归一化。
- `tests/test_exit_report.py`、`tests/test_exit_probe.py`、`tests/test_ip_info.py`：有意义的行为与故障验证。
- `README.md`：使用步骤、环境变量、数据库结构、查询和判断的限制。

## Global Constraints

- 使用 `venv/bin/python`，可执行 Python 入口为 `#!/usr/bin/env python`。
- 不启动独立 sing-box，不修改现有配置生成或路由代码。
- 主键是节点名称，不是出口 IP；不删除旧记录。
- 不提交、推送，不自动修改用户代理状态进行真实采集验证。

## Review Focus

1. 两个节点共用 IP：仍是两个节点记录，数据库查询复用。
2. 节点出口变化或本次探测失败：历史保留，当前结论不会错误套用旧 IP 属性。
3. 嵌套组循环或 GLOBAL 无法选择目标节点：改变状态前报错。
4. 切换或请求中断：恢复 GLOBAL 与模式，已完成项落盘，恢复失败可见。
5. 查询限流、源数据缺字段或冲突：不把缺失当否，不覆盖旧成功数据。

## Task 1: 节点数据库与汇总

**Files:** `common/exit_report.py`、`tests/test_exit_report.py`

**Interfaces:** 节点名到记录的数据库；`load_database(path)`、`save_database(path, data)`、`merge_observation(...)`、`summarize(...)`。

- [x] 先写失败测试：相同 IP 的不同节点不合并、旧节点保留、IP 变化与失败保留历史、缺失/冲突属性、损坏库不覆盖。
- [x] 运行 `venv/bin/python -m unittest discover -s tests -p test_exit_report.py -v` 确认失败原因。
- [x] 实现增量库、原子保存与互斥、按当前出口生成带来源的结论。
- [x] 重跑该测试文件并确认通过。

## Task 2: 本地代理采集

**Files:** `common/exit_probe.py`、`tests/test_exit_probe.py`

**Interfaces:** 通过 `collect` 编排 API 客户端和探测请求，逐节点调用 Task 1 的合并与保存。

- [x] 先写失败测试：递归组去重、循环/缺失引用、目标不可选、切换失败/探测超时/Ctrl-C 后恢复、明确代理请求、多个服务不同 IP。
- [x] 运行对应 unittest 文件确认失败，再实现 API 与采集；使用本地模拟 API/代理测试，避免改动真实代理状态。
- [x] 重跑测试，验证请求路径和恢复后的实际模拟状态。

## Task 3: IP 查询、命令入口与文档

**Files:** `common/ip_info.py`、`probe-exits.py`、`tests/test_ip_info.py`、`README.md`

**Interfaces:** `enrich` 对当前出口按 IP/来源补全并更新节点视图；`export` 按节点输出 CSV。

- [x] 先写失败测试：双来源映射、查询 IP 匹配、缓存复用、刷新失败保留旧值、429/额度耗尽停止来源、Key 不泄露、CSV 节点主键输出。
- [x] 运行对应 unittest 文件确认失败，再实现查询、命令入口与文档。
- [x] 用临时库运行 collect/enrich/export 的本地模拟集成检查；不消耗用户配额，不切换真实节点。
- [x] 运行 `venv/bin/python -m unittest discover -s tests -v`、各子命令 `--help` 和 `git diff --check`。
- [x] 审查最终 diff 与未跟踪文件，报告真实测试范围及尚未进行的真实节点/数据库联网验证。


## 执行结果

- 当前工作区完成实现，未提交、未推送；没有修改真实代理模式或节点选择。
- 完整测试：`venv/bin/python -m unittest discover -s tests -v`，80 项通过（2026-11-12）。
- 各子命令帮助、Python 编译检查、`git diff --check` 通过。
- 模拟端到端验证：真实 HTTP 模拟控制 API/代理 → 增量采集 → 两来源补全 → CSV；覆盖失败、Ctrl-C、恢复失败、限流、旧记录保留、多服务不同 IP。
- 独立审查修复：合法 nullable 归属响应、is_vpn truthy 值、CSV 查询/探测时间，均有回归测试。
- 真实接口验证：公开 IP 8.8.8.8 的 ip-api 查询成功；ipapi.is 经固定本地 HTTP 代理查询成功。Key 由交互 zsh 环境读取，未写入结果或日志。
- ipapi.is 直连出现 TLS EOF；可用 `proxy global ./probe-exits.py enrich` 选择现有 7898 入口，保留 TLS 校验。
- 未执行真实组的批量出口采集；真实节点切换恢复尚需实际使用验证。
- 后续修订：组名支持包含匹配；关键词匹配、组并集、节点去重和无匹配报错均已验证，CLI 模拟端到端改用部分组名。完整测试更新为 82 项通过。
- 后续修订：不再设置 trust_env=False，遵循 requests 默认环境配置。
- 后续修订：按用户要求移除 enrich 的内部代理参数及 LookupClient 的代理配置，完全由外部 proxy 包装命令或环境变量决定查询代理。
- 后续修订：enrich 自动使用两来源批量接口；新增 101 IP 分批、乱序映射和单项失败测试，完整测试 84 项通过。经现有 7898 入口对 8.8.8.8/1.1.1.1 做真实批量查询，两来源均成功；未修改用户数据库或 GLOBAL。默认 proxy 的 7890 入口仍出现 TLS EOF，使用 proxy global 可选择已验证可用的 7898 入口。

## SOPS 数据库扩展（用户已授权）

- 默认路径改为 `data/exits.sops.json`，`.sops.yaml` 复用原有 age 接收者；使用 binary store 整体加密，隐藏节点名/IP 等 JSON 键。
- `common.exit_report.load_database(path=DEFAULT_DATABASE)` 为共享只读入口，未来配置生成器可直接导入；当前不修改 `clash-to-sing.py` 的筛选行为。
- `save_database` 在内存序列化后通过管道交给 SOPS，临时文件仅写密文；验证旧库可读，内容相同不重加密，成功后原子替换。失败不回退明文、不覆盖旧库。
- `.sops.json` 后缀强制整体加密，显式普通 `.json` 仍兼容本地明文。`data/` 仅允许 SOPS JSON 入库，明文备份、CSV、锁文件保持忽略。
- 本次迁移原明文库，验证完整加解密往返一致，原 `reports/exits.json` 保留为本地备份；迁移过程不发出 IP 查询、不切换 GLOBAL。
- 新测试使用临时 age 密钥调用真实 SOPS，覆盖隐私、无变化保存、增量保留、错误密钥、篡改密文、加密失败和 CLI 全流程。
- 验证：完整测试 91 项通过；独立只读审查无阻断问题；真实库 55 个节点、18 个 IP 缓存迁移前后一致；跨工作目录读取默认库成功，无变化保存保持密文不变。
