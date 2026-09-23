import unittest

from common.certificate import attach_certificates, certificate_names, hostname_matches

# 自签 CA（SAN = www.bing.com, *.example.com），与 NanoCloud 订阅顶层 certificate 同形态
BING_CA = """-----BEGIN CERTIFICATE-----
MIIBrDCCAVGgAwIBAgIUW58l3HCuWSzN7rgRNr/4wsYfPr4wCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMd3d3LmJpbmcuY29tMB4XDTI2MDkyMzAzNTAzNloXDTM2MDky
MDAzNTAzNlowFzEVMBMGA1UEAwwMd3d3LmJpbmcuY29tMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEIsKWDhTsCL6Ez9+WsxitKQEHfg9K6H/p5qLYy+M3H17jKG2t
UhrcJ/2kCh3iLObfqROgU44z8ecZnO26h+DfhqN7MHkwHQYDVR0OBBYEFK5o+uSK
ce5tG3DmneeIkLzIB5NVMB8GA1UdIwQYMBaAFK5o+uSKce5tG3DmneeIkLzIB5NV
MA8GA1UdEwEB/wQFMAMBAf8wJgYDVR0RBB8wHYIMd3d3LmJpbmcuY29tgg0qLmV4
YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQD8Yy4qZNe+Qv6u1E+gl4ACfS3a
O+1Yb2+Bfc0Hzds+rQIhAK88dojA0I7how2IAWUBPD7+VjPMY8Wn5iyvZGHgBCXH
-----END CERTIFICATE-----
"""


def outbound(server_name=None, **tls):
    result = {"type": "tuic", "tag": "node", "server": "1.2.3.4", "tls": {"enabled": True, **tls}}
    if server_name:
        result["tls"]["server_name"] = server_name
    return result


class HostnameMatchesTest(unittest.TestCase):
    def test_exact_match_is_case_insensitive(self):
        self.assertTrue(hostname_matches("WWW.Bing.com", {"www.bing.com"}))

    def test_wildcard_matches_single_label(self):
        self.assertTrue(hostname_matches("a.example.com", {"*.example.com"}))
        self.assertFalse(hostname_matches("a.b.example.com", {"*.example.com"}))
        self.assertFalse(hostname_matches("example.com", {"*.example.com"}))

    def test_other_host_does_not_match(self):
        self.assertFalse(hostname_matches("mms-statlc-e.codeu.men", {"www.bing.com"}))


class CertificateNamesTest(unittest.TestCase):
    def test_reads_subject_alt_names(self):
        self.assertEqual({"www.bing.com", "*.example.com"}, certificate_names(BING_CA))

    def test_invalid_pem_yields_no_names(self):
        self.assertEqual(set(), certificate_names("not a certificate"))


class AttachCertificatesTest(unittest.TestCase):
    def attach(self, outbounds):
        attach_certificates(outbounds, [BING_CA])
        return outbounds

    def test_attaches_to_matching_server_name(self):
        (result,) = self.attach([outbound("www.bing.com", insecure=False)])
        self.assertEqual([BING_CA], result["tls"]["certificate"])

    def test_skips_other_server_name(self):
        # 出站级 certificate 会替换系统信任根，给真证书节点加上反而校验失败
        (result,) = self.attach([outbound("mms-statlc-e.codeu.men")])
        self.assertNotIn("certificate", result["tls"])

    def test_falls_back_to_server_without_server_name(self):
        node = outbound()
        node["server"] = "www.bing.com"
        (result,) = self.attach([node])
        self.assertEqual([BING_CA], result["tls"]["certificate"])

    def test_skips_insecure(self):
        (result,) = self.attach([outbound("www.bing.com", insecure=True)])
        self.assertNotIn("certificate", result["tls"])

    def test_keeps_existing_certificate(self):
        (result,) = self.attach([outbound("www.bing.com", certificate="OTHER")])
        self.assertEqual("OTHER", result["tls"]["certificate"])

    def test_skips_outbound_without_tls(self):
        (result,) = self.attach([{"type": "shadowsocks", "tag": "ss", "server": "www.bing.com"}])
        self.assertNotIn("tls", result)

    def test_skips_disabled_tls(self):
        (result,) = self.attach([outbound("www.bing.com", enabled=False)])
        self.assertNotIn("certificate", result["tls"])


if __name__ == "__main__":
    unittest.main()
