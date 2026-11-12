"""通过现有 Clash API 切换出口，经本地 HTTP 代理采集公网 IP。"""

import ipaddress
import sys
from urllib.parse import quote, urlparse

import requests

from common.exit_report import merge_observation, now, save_database


DEFAULT_ECHO_URLS = ['https://api.ipify.org?format=json', 'https://api.myip.com']
GROUP_TYPES = {'selector', 'urltest', 'fallback', 'loadbalance'}
EXCLUDED_TYPES = {'direct', 'reject', 'block', 'dns', 'pass', 'compatible'}


def match_groups(proxies, keywords):
    result = []
    for keyword in keywords:
        if not keyword:
            raise ValueError('分组关键词不能为空')
        matches = [name for name, item in proxies.items()
                   if keyword in name and item.get('type', '').lower() in {'selector', 'urltest'}]
        if not matches:
            raise ValueError(f'没有名称包含该关键词的 selector/urltest 分组: {keyword}')
        for name in matches:
            if name not in result:
                result.append(name)
    return result


def expand_groups(proxies, groups):
    result = {}

    def visit(name, root, ancestors):
        if name in ancestors:
            raise ValueError(f'分组循环引用: {name}')
        if name not in proxies:
            raise ValueError(f'节点或分组不存在: {name}')
        item = proxies[name]
        kind = item.get('type', '').lower()
        if kind in GROUP_TYPES:
            for child in item.get('all', []):
                visit(child, root, ancestors | {name})
        elif kind not in EXCLUDED_TYPES:
            memberships = result.setdefault(name, [])
            if root not in memberships:
                memberships.append(root)

    for group in groups:
        if group not in proxies or proxies[group].get('type', '').lower() not in {'selector', 'urltest'}:
            raise ValueError(f'不是 selector/urltest 分组: {group}')
        visit(group, group, set())
    if not result:
        raise ValueError('所选分组中没有可探测节点')
    return result


def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('地址必须是无用户名密码的 HTTP/HTTPS URL')


class Controller:
    def __init__(self, url, secret=None, timeout=10):
        validate_url(url)
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        if secret:
            self.session.headers['Authorization'] = f'Bearer {secret}'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def request(self, method, path, **kwargs):
        try:
            response = self.session.request(method, self.url + path, timeout=self.timeout, **kwargs)
            if not response.ok:
                raise RuntimeError(f'控制 API 返回 HTTP {response.status_code}')
            return response.json() if method == 'GET' else None
        except (requests.RequestException, ValueError) as exc:
            raise RuntimeError(f'控制 API 请求失败 ({type(exc).__name__})') from None


def probe_ip(proxy_url, echo_url, timeout=15):
    validate_url(proxy_url)
    validate_url(echo_url)
    try:
        # 单次请求独立连接，避免连接复用跨过节点切换。
        with requests.Session() as session:
            response = session.get(echo_url, proxies={'http': proxy_url, 'https': proxy_url},
                                   timeout=timeout, headers={'Connection': 'close'}, allow_redirects=False)
            if response.status_code != 200:
                raise RuntimeError(f'出口服务返回 HTTP {response.status_code}')
            try:
                data = response.json()
                value = data.get('ip') if isinstance(data, dict) else None
            except ValueError:
                value = response.text.strip()
            address = ipaddress.ip_address(value)
            if not address.is_global:
                raise ValueError('非公网地址')
            return str(address)
    except (requests.RequestException, ValueError, TypeError) as exc:
        raise RuntimeError(f'出口探测失败 ({type(exc).__name__})') from None


def collect(controller, proxy_url, groups, db, path, echo_urls=None, selector='GLOBAL', timeout=15):
    echo_urls = echo_urls or DEFAULT_ECHO_URLS
    validate_url(proxy_url)
    for url in echo_urls:
        validate_url(url)
    proxies = controller.request('GET', '/proxies')['proxies']
    matched = match_groups(proxies, groups)
    nodes = expand_groups(proxies, matched)
    print('匹配分组: ' + ', '.join(matched), file=sys.stderr)
    endpoint = '/proxies/' + quote(selector, safe='')
    selection = controller.request('GET', endpoint)
    if selection.get('type', '').lower() != 'selector' or not selection.get('now'):
        raise ValueError('控制出口必须是有当前选中项的 selector')
    missing = set(nodes) - set(selection.get('all', []))
    if missing:
        raise ValueError('控制出口无法直接选择节点: ' + ', '.join(sorted(missing)))
    mode = controller.request('GET', '/configs').get('mode')
    if not isinstance(mode, str) or not mode:
        raise ValueError('无法读取原始代理模式')
    if selector != 'GLOBAL':
        raise ValueError('目前仅支持 GLOBAL 控制出口，以确保 global 模式路由到所选节点')
    failures = 0
    try:
        controller.request('PATCH', '/configs', json={'mode': 'global'})
        if controller.request('GET', '/configs').get('mode', '').lower() != 'global':
            raise RuntimeError('控制 API 未切换到 global 模式')
        for index, (name, memberships) in enumerate(nodes.items(), 1):
            print(f'[{index}/{len(nodes)}] {name}', file=sys.stderr)
            switch_error = None
            try:
                controller.request('PUT', endpoint, json={'name': name})
                if controller.request('GET', endpoint).get('now') != name:
                    raise RuntimeError('控制 API 未切换到目标节点')
            except RuntimeError as exc:
                switch_error = str(exc)
            for url in dict.fromkeys(echo_urls):
                ip, error = None, switch_error
                if not error:
                    try:
                        ip = probe_ip(proxy_url, url, timeout)
                    except (RuntimeError, TimeoutError) as exc:
                        error = str(exc)
                if error:
                    failures += 1
                    print(f'  {url}: {error}', file=sys.stderr)
                merge_observation(db, name, memberships, url, ip, now(), error)
                save_database(path, db)
    finally:
        errors = []
        # 两项独立恢复，即使其中一项失败，也继续尝试另一项。
        for method, restore_path, payload, key, expected in [
            ('PUT', endpoint, {'name': selection['now']}, 'now', selection['now']),
            ('PATCH', '/configs', {'mode': mode}, 'mode', mode),
        ]:
            try:
                controller.request(method, restore_path, json=payload)
                if controller.request('GET', restore_path).get(key) != expected:
                    raise RuntimeError('恢复后状态不匹配')
            except RuntimeError as exc:
                errors.append(f'{key}: {exc}')
        if errors:
            raise RuntimeError('恢复代理状态失败，请检查本地代理：' + '; '.join(errors))
    return failures
