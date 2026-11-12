"""与节点切换无关的 IP 数据库查询和可恢复的增量补全。"""

import ipaddress
import sys
import time
from email.utils import parsedate_to_datetime

import requests

from common.exit_report import now, save_database


ENDPOINTS = {'ip-api': 'http://ip-api.com/json/{ip}', 'ip-api-batch': 'http://ip-api.com/batch',
             'ipapi.is': 'https://api.ipapi.is/'}
IP_API_FIELDS = ('status,message,query,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting')


def public_ip(value):
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError('只接受公网 IP')
    return str(address)


def _retry_seconds(value, default):
    try:
        return max(1, int(value))
    except (ValueError, TypeError):
        try:
            return max(1, parsedate_to_datetime(value).timestamp() - time.time())
        except (ValueError, TypeError, AttributeError, OverflowError):
            return default


class LookupClient:
    def __init__(self, api_key=None, timeout=15, endpoints=None):
        self.api_key = api_key
        self.timeout = timeout
        self.endpoints = endpoints or ENDPOINTS
        self.session = requests.Session()
        self.next_ip_api = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def redact(self, value):
        if isinstance(value, dict):
            return {self.redact(key): self.redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, str) and self.api_key:
            return value.replace(self.api_key, '[redacted]')
        return value

    def _request(self, source, ips, limits, bulk):
        limit = limits.get(source, {})
        if limit.get('not_before', 0) > time.time():
            raise RuntimeError('来源限流/拒绝访问，冷却期间跳过；恢复时间见 provider_limits')
        try:
            if source == 'ip-api':
                delay = self.next_ip_api - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                self.next_ip_api = time.monotonic() + (4.1 if bulk else 1.4)
                if bulk:
                    response = self.session.post(self.endpoints['ip-api-batch'], json=ips,
                                                 params={'fields': IP_API_FIELDS}, timeout=self.timeout,
                                                 allow_redirects=False)
                else:
                    response = self.session.get(self.endpoints[source].format(ip=ips[0]),
                                                params={'fields': IP_API_FIELDS}, timeout=self.timeout,
                                                allow_redirects=False)
                if response.headers.get('X-Rl') == '0':
                    limits[source] = {'not_before': time.time() + _retry_seconds(response.headers.get('X-Ttl'), 60),
                                      'reason': 'X-Rl=0'}
            elif source == 'ipapi.is':
                if not self.api_key:
                    raise RuntimeError('缺少 IPAPI_IS_KEY')
                payload = {'ips': ips, 'key': self.api_key} if bulk else {'q': ips[0], 'key': self.api_key}
                response = self.session.post(self.endpoints[source], json=payload,
                                             timeout=self.timeout, allow_redirects=False)
            else:
                raise ValueError('未知 IP 数据源')
            if response.status_code in (403, 429):
                seconds = _retry_seconds(response.headers.get('Retry-After'),
                                         86400 if source == 'ipapi.is' else 60)
                limits[source] = {'not_before': time.time() + seconds, 'reason': f'HTTP {response.status_code}'}
            if response.status_code != 200:
                raise RuntimeError(f'查询返回 HTTP {response.status_code}')
            data = response.json()
            if isinstance(data, dict) and (data.get('error') or data.get('error_code')):
                raise RuntimeError('IP 数据库查询未成功')
            return data
        except (requests.RequestException, ValueError, TypeError) as exc:
            # 不使用 requests 异常的文本，它可能含 URL、请求信息或凭证。
            raise RuntimeError(f'IP 查询失败 ({type(exc).__name__})') from None

    def _validate(self, source, ip, data):
        try:
            if not isinstance(data, dict):
                raise RuntimeError('IP 数据库响应格式错误')
            if source == 'ip-api':
                if data.get('status') != 'success':
                    raise RuntimeError('ip-api 查询未成功')
                returned_ip = data.get('query')
            else:
                if data.get('error') or data.get('error_code'):
                    raise RuntimeError('ipapi.is 查询未成功')
                # 完整查询可合法没有归属/地理/BGP 数据；安全标记仍然有用。
                # 匿名缩减版没有检测标记，不能仅凭 nullable 归属字段认定为完整结果。
                if ('is_datacenter' not in data or data.get('docs') or
                        not all(data.get(key) is None or isinstance(data[key], dict)
                                for key in ('location', 'company', 'asn'))):
                    raise RuntimeError('ipapi.is 未返回完整的带 Key 数据')
                returned_ip = data.get('ip')
            if public_ip(returned_ip) != ip:
                raise RuntimeError('数据库返回的 IP 与查询 IP 不一致')
            return self.redact(data)
        except (ValueError, TypeError) as exc:
            raise RuntimeError(f'IP 数据库数据无效 ({type(exc).__name__})') from None

    def lookup(self, source, ip, limits):
        ip = public_ip(ip)
        return self._validate(source, ip, self._request(source, [ip], limits, bulk=False))

    def lookup_batch(self, source, ips, limits):
        ips = list(dict.fromkeys(public_ip(ip) for ip in ips))
        if not 1 <= len(ips) <= 100:
            raise ValueError('单批需要 1 到 100 个不同公网 IP')
        data = self._request(source, ips, limits, bulk=True)
        duplicates = set()
        if source == 'ip-api':
            if not isinstance(data, list):
                raise RuntimeError('ip-api 批量响应不是数组')
            items = {}
            for item in data:
                if not isinstance(item, dict):
                    continue
                try:
                    ip = public_ip(item.get('query'))
                except (ValueError, TypeError):
                    continue
                if ip in items:
                    duplicates.add(ip)
                items[ip] = item
        else:
            if not isinstance(data, dict):
                raise RuntimeError('ipapi.is 批量响应不是对象')
            # 元数据（如 total_elapsed_ms）不会被当作 IP 条目。
            items = {}
            for key, item in data.items():
                try:
                    ip = public_ip(key)
                except (ValueError, TypeError):
                    continue
                if ip in items:
                    duplicates.add(ip)
                items[ip] = item
        result = {}
        for ip in ips:
            if ip in duplicates:
                result[ip] = {'error': '批量响应包含重复 IP'}
            elif ip not in items:
                result[ip] = {'error': '批量响应缺少该 IP 的结果'}
            else:
                try:
                    result[ip] = {'data': self._validate(source, ip, items[ip])}
                except RuntimeError as exc:
                    result[ip] = {'error': str(exc)}
        return result


def enrich(db, path, client, refresh=False, ips=None):
    addresses = list(dict.fromkeys([
        *(public_ip(item['ip']) for node in db['nodes'].values() for item in node['current'].values()),
        *(public_ip(ip) for ip in (ips or [])),
    ]))
    sources = ['ip-api', 'ipapi.is'] if client.api_key else ['ip-api']
    if not client.api_key:
        print('未设置 IPAPI_IS_KEY：仅查询 ip-api.com', file=sys.stderr)
    failures = 0
    limits = db.setdefault('provider_limits', {})
    for ip in addresses:
        db['ip_cache'].setdefault(ip, {'sources': {}})
    for source in sources:
        pending = [ip for ip in addresses
                   if refresh or not db['ip_cache'][ip]['sources'].get(source, {}).get('data')]
        for offset in range(0, len(pending), 100):
            batch = pending[offset:offset + 100]
            print(f'{source}: 批量查询 {len(batch)} 个 IP ({offset + len(batch)}/{len(pending)})', file=sys.stderr)
            attempted_at = now()
            try:
                results = client.lookup_batch(source, batch, limits)
            except RuntimeError as exc:
                results = {ip: {'error': str(exc)} for ip in batch}
            for ip in batch:
                entry = db['ip_cache'][ip]['sources'].setdefault(source, {})
                entry['last_attempt'] = attempted_at
                result = results[ip]
                if 'data' in result:
                    entry.update(data=result['data'], queried_at=now())
                    entry.pop('error', None)
                else:
                    entry['error'] = result['error']
                    failures += 1
                    print(f'  {ip}: {entry["error"]}', file=sys.stderr)
            save_database(path, db)
    return failures
