#!/usr/bin/env python
"""
将 fake_ip_filter.list 格式转换为 sing-box rule-set JSON 格式。

转换规则：
1. 不含 * 和 + 的行 → domain（精确匹配）
2. 以 +. 或 *. 开头且其余部分不含通配符的行 → domain_suffix（去掉开头的前缀）
3. 其它含有 * 或 + 的行 → domain_regex（* → [^.]+ ，+ → .+，点号转义，添加首尾锚点）
"""

import json
from pathlib import Path
from typing import Optional

import typer


def to_domain_regex(pattern: str) -> str:
    """将含通配符的模式转换为正则表达式。"""
    result = ""
    for ch in pattern:
        if ch == "*":
            result += "[^.]+"
        elif ch == "+":
            result += ".+"
        elif ch in r"\.^${}[]()|-":
            result += "\\" + ch
        else:
            result += ch
    return f"^{result}$"


def classify(line: str) -> tuple[str, str]:
    """
    返回 (type, value)，type 为 'domain' / 'domain_suffix' / 'domain_regex'。
    """
    has_star = "*" in line
    has_plus = "+" in line

    if not has_star and not has_plus:
        return "domain", line

    # 以 +. 或 *. 开头且其余部分无通配符 → domain_suffix
    if line.startswith("+.") or line.startswith("*."):
        rest = line[2:]
        if "*" not in rest and "+" not in rest:
            return "domain_suffix", "." + rest

    # 其余情况 → domain_regex
    return "domain_regex", to_domain_regex(line)


def convert(input_path: Path) -> dict:
    domains: list[str] = []
    domain_suffixes: list[str] = []
    domain_regexes: list[str] = []

    with open(input_path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            # 跳过注释和空行
            if not line or line.startswith("#"):
                continue
            # 跳过含空格的非域名条目（如 "Mijia Cloud"）
            if " " in line:
                continue

            kind, value = classify(line)
            if kind == "domain":
                domains.append(value)
            elif kind == "domain_suffix":
                domain_suffixes.append(value)
            else:
                domain_regexes.append(value)

    rule: dict = {}
    if domains:
        rule["domain"] = sorted(domains)
    if domain_suffixes:
        rule["domain_suffix"] = sorted(domain_suffixes)
    if domain_regexes:
        rule["domain_regex"] = domain_regexes  # 保持原始顺序

    return {"version": 1, "rules": [rule]}


app = typer.Typer()


@app.command()
def main(
    input_file: Path = typer.Argument(..., help="输入 .list 文件路径", exists=True),
    output_file: Optional[Path] = typer.Option(None, "-o", "--output", help="输出 JSON 文件路径（默认输出到标准输出）"),
) -> None:
    """将 fake_ip_filter.list 转换为 sing-box rule-set JSON"""
    result = convert(input_file)
    output_str = json.dumps(result, ensure_ascii=False, indent=2)

    if output_file:
        output_file.write_text(output_str + "\n", encoding="utf-8")
    else:
        typer.echo(output_str)


if __name__ == "__main__":
    app()
