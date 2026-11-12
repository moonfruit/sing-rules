"""以节点名称为主键的出口观测库；旧节点、观测和来源只增不删。"""

import csv
import fcntl
import ipaddress
import json
import os
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = PROJECT_ROOT / 'data' / 'exits.sops.json'
SOPS_CONFIG = PROJECT_ROOT / '.sops.yaml'


def _sops(operation, path, content=None):
    """整库作为 binary 加密；明文只通过管道和内存传递。"""
    command = ['sops', '--config', str(SOPS_CONFIG), operation,
               '--input-type', 'binary', '--output-type', 'binary']
    if operation == 'encrypt':
        command.extend(['--filename-override', str(path.resolve())])
    else:
        command.append(str(path))
    try:
        result = subprocess.run(command, input=content, capture_output=True, timeout=60)
    except FileNotFoundError:
        raise RuntimeError('读写加密数据库需要安装 sops') from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'SOPS {operation} 超时，数据库未被覆盖') from None
    if result.returncode:
        # stderr 可能包含身份路径等敏感信息，不写入日志或数据库。
        raise RuntimeError(f'SOPS {operation} 失败（退出码 {result.returncode}），'
                           '请检查 .sops.yaml 和 age 密钥；数据库未被覆盖')
    return result.stdout


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def new_database():
    return {'schema_version': 1, 'nodes': {}, 'ip_cache': {}}


@contextmanager
def database_lock(path):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    # 锁文件必须保留，删除会让另一个进程锁住不同 inode。
    with path.with_name(path.name + '.lock').open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('数据库正在被另一个进程使用') from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def load_database(path=DEFAULT_DATABASE):
    """读取节点库；未来配置生成器可直接调用，不需要代理或网络依赖。"""
    path = Path(path)
    if not path.exists():
        return new_database()
    try:
        if path.name.endswith('.sops.json'):
            envelope = json.loads(path.read_bytes())
            if not isinstance(envelope, dict) or set(envelope) != {'data', 'sops'}:
                raise ValueError('加密数据库必须是 SOPS binary 格式，不能保存明文或暴露 JSON 键名')
            db = json.loads(_sops('decrypt', path))
        else:
            db = json.loads(path.read_text())
        if not isinstance(db, dict) or db.get('schema_version') != 1:
            raise ValueError('不支持的数据库版本')
        if not isinstance(db['nodes'], dict) or not isinstance(db['ip_cache'], dict):
            raise ValueError('无效的数据库结构')
        for node in db['nodes'].values():
            if not isinstance(node, dict):
                raise ValueError('无效的节点记录')
            for key, kind in [('current', dict), ('observations', list), ('groups', list), ('last_attempts', dict)]:
                if not isinstance(node.get(key), kind):
                    raise ValueError('无效的节点字段: ' + key)
            for observation in node['current'].values():
                ipaddress.ip_address(observation['ip'])
        for ip, cache in db['ip_cache'].items():
            ipaddress.ip_address(ip)
            if not isinstance(cache.get('sources'), dict):
                raise ValueError('无效的 IP 缓存')
        return db
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f'数据库损坏或版本不兼容: {path}') from exc


def save_database(path, db):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for node in db['nodes'].values():
        node['summary'] = summarize(db, node)
    # 同时验证旧库可读；内容不变时不重新生成随机密文，避免无意义 Git 差异。
    if path.exists() and load_database(path) == db:
        return
    content = (json.dumps(db, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if path.name.endswith('.sops.json'):
        content = _sops('encrypt', path, content)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=path.parent,
                                         prefix='.' + path.name + '.', delete=False) as handle:
            temporary = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def merge_observation(db, name, groups, service, ip, timestamp, error=None):
    if ip is not None:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            raise ValueError('出口必须是公网 IP')
        ip = str(address)
    node = db['nodes'].setdefault(name, {
        'groups': [], 'first_seen': timestamp, 'last_seen': timestamp,
        'current': {}, 'observations': [], 'last_attempts': {},
    })
    node['groups'] = list(dict.fromkeys([*node['groups'], *groups]))
    node['last_seen'] = timestamp
    attempt = {'service': service, 'attempted_at': timestamp, 'status': 'ok' if ip else 'error'}
    if ip:
        attempt.update(ip=ip, family=ipaddress.ip_address(ip).version)
        node['current'][service] = {'ip': ip, 'observed_at': timestamp, 'family': attempt['family']}
    else:
        attempt['error'] = error or '未获取到 IP'
    node['observations'].append(attempt)
    node['last_attempts'][service] = attempt.copy()


def _any_flag(data, keys):
    values = [data[key] for key in keys if isinstance(data.get(key), bool)]
    if True in values:
        return True
    # 部分标记缺失时，不能用剩下的 false 推断整体为 false。
    return False if len(values) == len(keys) else None


def _vpn_flag(value):
    # ipapi.is 的 is_vpn 详情要求按 JS truthiness 判断，不保证严格为 bool。
    if value is None:
        return None
    return True if isinstance(value, (dict, list)) else bool(value)


def source_fields(source, data):
    if source == 'ip-api':
        asn = data.get('as', '').split(' ', 1)[0] or None
        return dict(country_code=data.get('countryCode'), region=data.get('regionName'), city=data.get('city'),
                    isp=data.get('isp'), organization=data.get('org'), asn=asn, hosting=data.get('hosting'),
                    proxy=data.get('proxy'), mobile=data.get('mobile'))
    if source == 'ipapi.is':
        location, company, asn = (data.get(key) or {} for key in ('location', 'company', 'asn'))
        vpn = _vpn_flag(data.get('is_vpn'))
        flags = {**data, 'is_vpn': vpn}
        return dict(country_code=location.get('country_code'), region=location.get('state'), city=location.get('city'),
                    isp=asn.get('org'), organization=company.get('name'),
                    asn=f"AS{asn['asn']}" if asn.get('asn') else None,
                    hosting=data.get('is_datacenter'), proxy=_any_flag(flags, ['is_proxy', 'is_vpn', 'is_tor']),
                    vpn=vpn, tor=data.get('is_tor'), mobile=data.get('is_mobile'),
                    network_type=company.get('type'), asn_type=asn.get('type'))
    return {}


FIELDS = ('country_code', 'region', 'city', 'isp', 'organization', 'asn', 'hosting', 'proxy',
          'vpn', 'tor', 'mobile', 'network_type', 'asn_type', 'residential')


def summarize(db, node):
    result = {}
    for observation in node['current'].values():
        ip = observation['ip']
        sources = db['ip_cache'].get(ip, {}).get('sources', {})
        normalized = {source: source_fields(source, entry['data']) for source, entry in sources.items()
                      if 'data' in entry}
        fields = {}
        for field in FIELDS:
            votes = {source: values[field] for source, values in normalized.items()
                     if values.get(field) is not None and values[field] != ''}
            distinct = list(dict.fromkeys(votes.values()))
            fields[field] = {'value': distinct[0] if len(distinct) == 1 else None,
                             'conflict': len(distinct) > 1, 'sources': votes}
        result[ip] = {
            'fields': fields,
            'residential_note': 'ISP 类型不等于家宽；当前来源没有足以确认家宽的字段',
            'sources': {name: {key: value for key, value in entry.items() if key != 'data'}
                        for name, entry in sources.items()},
        }
    return result


def export_csv(db, handle):
    columns = ['node', 'groups', 'service', 'ip', 'family', 'observed_at', 'probe_attempted_at',
               'probe_status', 'probe_error', *FIELDS, 'conflicts', 'query_times', 'query_errors']
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for name, node in db['nodes'].items():
        summaries = summarize(db, node)
        for service in dict.fromkeys([*node['current'], *node['last_attempts']]):
            observation = node['current'].get(service, {})
            attempt = node['last_attempts'].get(service, {})
            summary = summaries.get(observation.get('ip'), {})
            fields = summary.get('fields', {})
            row = dict(node=name, groups=' | '.join(node['groups']), service=service,
                       **observation, probe_attempted_at=attempt.get('attempted_at'),
                       probe_status=attempt.get('status'), probe_error=attempt.get('error', ''))
            for field in FIELDS:
                value = fields.get(field, {}).get('value')
                row[field] = 'conflict' if fields.get(field, {}).get('conflict') else (
                    'unknown' if value is None else value)
            row['conflicts'] = json.dumps({key: value['sources'] for key, value in fields.items()
                                           if value['conflict']}, ensure_ascii=False)
            row['query_times'] = json.dumps({key: {'queried_at': value.get('queried_at'),
                                                   'last_attempt': value.get('last_attempt')}
                                             for key, value in summary.get('sources', {}).items()}, ensure_ascii=False)
            row['query_errors'] = json.dumps({key: value['error'] for key, value in summary.get('sources', {}).items()
                                              if value.get('error')}, ensure_ascii=False)
            writer.writerow(row)
