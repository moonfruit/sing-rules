"""
订阅自带 CA 证书的处理

部分 sing-box 订阅不再用 `insecure: true`，而是在顶层 `certificate.certificate` 下发自签 CA，
节点 `tls.insecure: false`。转换只取 outbounds 会丢掉这张 CA，导致所有依赖它的节点校验失败。

这里把 CA 下放到 SAN 与 `server_name` 匹配的出站 `tls.certificate`，而不是合并到全局：
- 出站级 certificate 会替换系统信任根，给用真证书的节点加上反而校验失败；
- 全局信任一张机场持有私钥的 CA，等于允许它对该域名做中间人。
"""

import ssl
import tempfile
from pathlib import Path
from typing import Any, Iterable


def certificate_names(pem: str) -> set[str]:
    """读取 PEM 证书的 DNS SAN（无 SAN 时退回 CN），解析失败返回空集"""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "cert.pem"
        path.write_text(pem)
        try:
            # 标准库无公开的证书解析接口，_test_decode_cert 自 Python 2.7 起稳定存在
            decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
        except (ssl.SSLError, OSError, ValueError):
            return set()
    names = {value.lower() for kind, value in decoded.get("subjectAltName", ()) if kind == "DNS"}
    if not names:
        names = {value.lower() for rdn in decoded.get("subject", ()) for key, value in rdn if key == "commonName"}
    return names


def hostname_matches(hostname: str, names: Iterable[str]) -> bool:
    """按 RFC 6125 匹配主机名：通配符只覆盖最左侧一个完整标签"""
    hostname = hostname.lower().rstrip(".")
    for name in names:
        if name == hostname:
            return True
        if name.startswith("*."):
            head, _, tail = hostname.partition(".")
            if head and tail == name[2:]:
                return True
    return False


def attach_certificates(outbounds: Iterable[dict[str, Any]], pems: Iterable[str]):
    """把 SAN 匹配的 CA 写进出站 tls.certificate；已配 insecure 或自带证书的出站不动"""
    certs = [(pem, names) for pem in pems if (names := certificate_names(pem))]
    if not certs:
        return
    for outbound in outbounds:
        tls = outbound.get("tls")
        if not tls or not tls.get("enabled") or tls.get("insecure"):
            continue
        if "certificate" in tls or "certificate_path" in tls:
            continue
        hostname = tls.get("server_name") or outbound.get("server", "")
        if matched := [pem for pem, names in certs if hostname_matches(hostname, names)]:
            tls["certificate"] = matched
