#!/usr/bin/env python
"""采集本地代理节点出口，再独立查询 IP 信息和导出节点表。"""

import argparse
import os
import signal
import sys
from pathlib import Path

from common.exit_probe import Controller, collect
from common.exit_report import database_lock, export_csv, load_database
from common.ip_info import LookupClient, enrich


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest='command', required=True)
    for command, help_text in [('collect', '通过本地 API 采集组内节点出口 IP'),
                               ('enrich', '独立查询 IP 数据库并增量合并'), ('export', '按节点导出 CSV')]:
        sub = commands.add_parser(command, help=help_text, description=help_text)
        sub.add_argument('--database', type=Path, default=Path('reports/exits.json'), help='增量数据库路径')
        if command == 'collect':
            sub.add_argument('--group', action='append', required=True,
                             help='组名包含的关键词（区分大小写），匹配所有 selector/urltest 组，可重复')
            sub.add_argument('--api', default='http://127.0.0.1:9999', help='Clash API；密钥用 CLASH_API_SECRET')
            sub.add_argument('--proxy', default='http://127.0.0.1:7898', help='本地 HTTP/mixed 代理入口')
            sub.add_argument('--echo-url', action='append', help='出口 IP 服务，支持 JSON ip 或纯文本，可重复')
        elif command == 'enrich':
            sub.add_argument('--refresh', action='store_true', help='刷新已有成功来源，失败时保留旧值')
            sub.add_argument('--ip', action='append', help='额外查询公网 IP，可重复；不创建虚拟节点')
        else:
            sub.add_argument('--output', type=Path, help='CSV 输出路径，默认标准输出')
        if command != 'export':
            sub.add_argument('--timeout', type=float, default=15, help='单次网络请求超时秒数')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if getattr(args, 'timeout', 1) <= 0:
        parser().error('--timeout 必须大于 0')

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        with database_lock(args.database):
            db = load_database(args.database)
            if args.command == 'collect':
                with Controller(args.api, os.environ.get('CLASH_API_SECRET'), args.timeout) as controller:
                    failures = collect(controller, args.proxy, args.group, db, args.database,
                                       args.echo_url, timeout=args.timeout)
            elif args.command == 'enrich':
                with LookupClient(os.environ.get('IPAPI_IS_KEY'), args.timeout) as client:
                    failures = enrich(db, args.database, client, args.refresh, args.ip)
            else:
                if not args.database.exists():
                    raise ValueError('数据库不存在，请先采集')
                if args.output:
                    if args.output.resolve() == args.database.resolve():
                        raise ValueError('CSV 输出不能覆盖数据库')
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    with args.output.open('w', encoding='utf-8-sig', newline='') as handle:
                        export_csv(db, handle)
                else:
                    export_csv(db, sys.stdout)
                failures = 0
        return 1 if failures else 0
    except KeyboardInterrupt:
        print('已中断；已完成项已保存，采集阶段已尝试恢复代理状态', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f'错误：{exc}', file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    sys.exit(main())
