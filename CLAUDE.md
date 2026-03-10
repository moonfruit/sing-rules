# sing-rules

sing-box 规则集生成工具，基于 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)。

## 项目概述

将 v2ray geo 数据、Clash 规则列表转换为 sing-box rule-set 格式（`.json` + `.srs`），
同时支持将 Clash 订阅配置转换为 sing-box 完整出站配置。

## 关键脚本

| 脚本 | 用途 |
|------|------|
| `build-sing-rules.sh` | 主构建脚本：geo 转换 → Clash 规则合并 → 编译 `.srs` |
| `build-sing-config.sh` | 构建 sing-box 完整配置（含出站、路由规则） |
| `subscribe.sh <url> <output> [client]` | 下载订阅文件，保存流量信息到 `.info` |
| `clash-download.sh <list>` | 批量下载 Clash 规则列表 |
| `clash-merge.sh [--enable-process] <dir>` | 合并目录内 Clash 规则到 sing rule-set |
| `commit-and-push.sh` | 提交并推送 rules/ 目录更改 |
| `npm-publish.sh` | 发布到 npm（`@dkmoonfruit/sing-rules`） |

## Python 脚本

| 脚本 | 用途 |
|------|------|
| `geo-to-sing-rules.py` | 从 sing-box geo 数据库导出各分类规则集 JSON |
| `clash-to-sing-rules.py` | 将单个 Clash `.list` 文件合并到 sing rule-set JSON |
| `clash-to-sing.py` | 将 Clash/sing-box 订阅转换为 sing-box 出站+路由配置 |
| `filter-to-sing-rules.py` | 将 `fake_ip_filter.list` 转为 sing rule-set JSON |
| `copy-config.py` | 从主配置提取出站用于 iPhone 配置 |
| `split-outbounds.py` | 拆分出站配置 |
| `locate.py` | IP/域名归属地查询 |

## Python 公共库（`common/`）

- `common.py`：`Rule`、`merge`、`get_set`、`get_list`、`as_rule`、`domain_sort_key` 等工具函数
- `io.py`：`open_path`（支持 `-` 标准输入/输出）
- `object.py`：`as_hashable`、`copy_without_tag`、`simplify_dict`
- `outbound.py`：`safe_find_country`（IP 归属地检测）
- `yaml.py`：PyYAML 封装

## 目录结构

```
config/         # 订阅配置（config.json 定义数据源）
  iphone/       # iPhone 专用配置片段
config/config.json # 订阅列表（ConfigFile 格式，含 name/cost/format/emby）
dat/            # v2ray 原始 geo 数据（geoip.dat / geosite.dat）
preflight/      # 预处理脚本及 saved-countries.json（节点国家缓存）
rules/          # 输出目录：*.json（源码格式）+ *.srs（二进制格式）
zoo/            # 额外规则资源
```

## 依赖

**外部命令行工具：**
- `sing-box`：规则集编译（`rule-set compile/format`）、geo 导出、配置格式化/合并
- `geo`：v2ray geo 数据转换（`geo convert ip/site`）

**Python 包（`requirements.txt`）：**
- `typer`、`attrs`、`cattrs`、`pyyaml`、`requests`、`tldextract`

**Python 环境：** 使用项目内 `venv/`，解释器路径 `venv/bin/python3`

## 构建流程

```bash
# 完整规则集构建
./build-sing-rules.sh

# 构建 sing-box 配置（需要 private/ 目录）
./build-sing-config.sh [gitee_token]
```

`build-sing-rules.sh` 执行顺序：
1. 清理 `rules/` 下旧文件
2. 转换 `dat/` 中 v2ray geo 数据为 sing-box 格式
3. `geo-to-sing-rules.py` 导出各分类规则 JSON
4. 下载 `clash-list.txt` 中的 Clash 规则
5. `clash-merge.sh` 合并 Clash 规则及 `config/` 目录中的本地规则
6. `sing-box rule-set format/compile` 编译所有 `.json` 为 `.srs`
7. 若存在 `private/` 目录，同步 rules 到其中

## 规则集命名约定

- `@CN` 后缀：国内版本（直连）
- `@!CN` 后缀：非国内版本（代理）
- `dev-cn.json`、`games-cn.json` 等：国内对应规则

## `clash-to-sing.py` 关键行为

- 支持格式：`clash`、`shadow-rocket`、`sing-box`
- 节点分组：按国旗 emoji 或国家代码自动归组（HK/JP/SG/US 等）
- 成本标记：`cost < 1.5` 为省流节点（🛢️），`cost > 1` 为高级节点（👍）
- 协议标记：hy2（🌪️）、ss（🚀）、trojan（🐴）、tuic（🦬）、vless（🦢）、vmess（🐙）
- 国家检测：`preflight/saved-countries.json` 缓存节点归属地
- CDN：规则集通过 `fastly.jsdelivr.net` 分发（或 Gitee 私有）
