# sing-rules

Based on [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)

订阅配置 `config/config.json` 中的 `natural_selection` 声明该订阅参与的自然选择分组，
可选值为 `AI`、`Claude`、`ChatGPT`，省略时不参与这三个分组。目前仅 Ash 配置了
`"natural_selection": ["AI", "Claude", "ChatGPT"]`。
Claude 仍仅使用美国节点，AI 和 ChatGPT 仍仅使用美国和日本节点；手动选择不受此字段影响。
