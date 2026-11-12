import json
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from common import exit_probe as probe
from common.exit_report import new_database, load_database


@contextmanager
def local_proxy():
    state = {'mode': 'rule', 'selected': 'A', 'seen': [], 'fail': None,
             'disconnects': 0, 'plain': False}
    proxies = {
        'GLOBAL': {'type': 'Selector', 'all': ['A', 'B', 'DIRECT'], 'now': 'A'},
        'G': {'type': 'Selector', 'all': ['Nested', 'A', 'DIRECT']},
        'Nested': {'type': 'URLTest', 'all': ['A', 'B']},
        'A': {'type': 'Shadowsocks'}, 'B': {'type': 'Trojan'}, 'DIRECT': {'type': 'Direct'},
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, data, status=200):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/proxies':
                self.reply({'proxies': proxies})
            elif self.path == '/proxies/GLOBAL':
                self.reply({**proxies['GLOBAL'], 'now': state['selected']})
            elif self.path == '/configs':
                self.reply({'mode': state['mode']})
            elif self.path == 'http://echo.test/ip':
                state['seen'].append((state['mode'], state['selected']))
                if state['disconnects']:
                    state['disconnects'] -= 1
                    self.close_connection = True
                    return
                if state['plain']:
                    body = b'8.8.8.8\n'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.reply({'ip': '8.8.8.8' if state['selected'] == 'A' else '1.1.1.1'})
            elif self.path == 'http://echo.test/blocked':
                state['seen'].append((state['mode'], state['selected']))
                self.reply({}, 403)
            else:
                self.reply({}, 404)

        def do_PUT(self):
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if data['name'] == state['fail']:
                self.reply({}, 503)
            else:
                state['selected'] = data['name']
                self.reply({})

        def do_PATCH(self):
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            state['mode'] = data['mode']
            self.reply({})

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', state, proxies
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class ExitProbeTest(unittest.TestCase):
    def test_transient_disconnect_retries_with_new_connection_and_accepts_plain_ip(self):
        with local_proxy() as (url, state, _):
            state.update(disconnects=1, plain=True)
            self.assertEqual('8.8.8.8', probe.probe_ip(url, 'http://echo.test/ip'))
            self.assertEqual(2, len(state['seen']))

    def test_network_retry_is_bounded_and_403_is_not_retried(self):
        with local_proxy() as (url, state, _):
            state['disconnects'] = 3
            with self.assertRaises(RuntimeError):
                probe.probe_ip(url, 'http://echo.test/ip')
            self.assertEqual(2, len(state['seen']))
            state['seen'].clear()
            with self.assertRaisesRegex(RuntimeError, '403'):
                probe.probe_ip(url, 'http://echo.test/blocked')
            self.assertEqual(1, len(state['seen']))

    def test_one_blocked_echo_does_not_mark_nodes_failed_if_another_returns_ips(self):
        with local_proxy() as (url, state, _), tempfile.TemporaryDirectory() as directory:
            db = new_database()
            with probe.Controller(url) as controller:
                failures = probe.collect(controller, url, ['Nest'], db, Path(directory) / 'db.json',
                                         ['http://echo.test/blocked', 'http://echo.test/ip'])
            self.assertEqual(0, failures)
            self.assertEqual({'A', 'B'}, set(db['nodes']))
            self.assertTrue(all(node['current'] for node in db['nodes'].values()))
            self.assertTrue(all(node['last_attempts']['http://echo.test/blocked']['status'] == 'error'
                                for node in db['nodes'].values()))
            self.assertEqual(('rule', 'A'), (state['mode'], state['selected']))

    def test_group_keywords_match_all_containing_groups_and_deduplicate_nodes(self):
        proxies = {
            'ABC': {'type': 'Selector', 'all': ['A']},
            '机场 ABC 自动': {'type': 'URLTest', 'all': ['A', 'B']},
            '其它': {'type': 'Selector', 'all': ['C']},
            'A': {'type': 'Trojan'}, 'B': {'type': 'Trojan'}, 'C': {'type': 'Trojan'},
            'ABC 普通节点': {'type': 'Trojan'},
        }
        matched = probe.match_groups(proxies, ['ABC', '自动'])
        self.assertEqual(['ABC', '机场 ABC 自动'], matched)
        self.assertEqual({'A': ['ABC', '机场 ABC 自动'], 'B': ['机场 ABC 自动']},
                         probe.expand_groups(proxies, matched))

    def test_group_keyword_requires_a_nonempty_case_sensitive_group_match(self):
        proxies = {'ABC': {'type': 'Selector', 'all': []}, '仅节点': {'type': 'Trojan'}}
        for keyword in ['', 'abc', '不存在', '仅节点']:
            with self.subTest(keyword=keyword), self.assertRaises(ValueError):
                probe.match_groups(proxies, [keyword])

    def test_groups_expand_deduplicate_and_validate_before_changes(self):
        with local_proxy() as (url, state, proxies):
            self.assertEqual({'A': ['G', 'Nested'], 'B': ['G', 'Nested']},
                             probe.expand_groups(proxies, ['G', 'Nested']))
            proxies['Nested']['all'].append('G')
            with self.assertRaises(ValueError):
                probe.expand_groups(proxies, ['G'])
            self.assertEqual('rule', state['mode'])
            proxies['Nested']['all'] = ['missing']
            with self.assertRaises(ValueError):
                probe.expand_groups(proxies, ['G'])

    def test_real_http_control_and_proxy_requests_restore_state_and_checkpoint(self):
        with local_proxy() as (url, state, _), tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'db.json'
            db = new_database()
            with probe.Controller(url) as controller:
                failures = probe.collect(controller, url, ['G'], db, path, ['http://echo.test/ip'])
            self.assertEqual(0, failures)
            self.assertEqual([('global', 'A'), ('global', 'B')], state['seen'])
            self.assertEqual(('rule', 'A'), (state['mode'], state['selected']))
            saved = load_database(path)
            self.assertEqual('1.1.1.1', saved['nodes']['B']['current']['http://echo.test/ip']['ip'])

    def test_switch_failure_does_not_probe_wrong_node_and_restores(self):
        with local_proxy() as (url, state, _), tempfile.TemporaryDirectory() as directory:
            state['fail'] = 'B'
            db = new_database()
            with probe.Controller(url) as controller:
                failures = probe.collect(controller, url, ['G'], db, Path(directory) / 'db.json',
                                         ['http://echo.test/ip'])
            self.assertEqual(1, failures)
            self.assertEqual([('global', 'A')], state['seen'])
            self.assertEqual({}, db['nodes']['B']['current'])
            self.assertEqual(('rule', 'A'), (state['mode'], state['selected']))

    def test_interrupt_and_probe_timeout_restore_original_settings(self):
        for error in (KeyboardInterrupt(), TimeoutError('timeout')):
            with self.subTest(error=type(error).__name__), local_proxy() as (url, state, _):
                with tempfile.TemporaryDirectory() as directory, probe.Controller(url) as controller:
                    with patch.object(probe, 'probe_ip', side_effect=error):
                        if isinstance(error, KeyboardInterrupt):
                            with self.assertRaises(KeyboardInterrupt):
                                probe.collect(controller, url, ['G'], new_database(),
                                              Path(directory) / 'db.json', ['http://echo.test/ip'])
                        else:
                            self.assertEqual(2, probe.collect(controller, url, ['G'], new_database(),
                                                             Path(directory) / 'db.json', ['http://echo.test/ip']))
                self.assertEqual(('rule', 'A'), (state['mode'], state['selected']))

    def test_global_missing_target_fails_without_changing_state(self):
        with local_proxy() as (url, state, proxies), tempfile.TemporaryDirectory() as directory:
            proxies['GLOBAL']['all'] = ['A']
            with probe.Controller(url) as controller, self.assertRaises(ValueError):
                probe.collect(controller, url, ['G'], new_database(), Path(directory) / 'db.json',
                              ['http://echo.test/ip'])
            self.assertEqual(('rule', 'A', []), (state['mode'], state['selected'], state['seen']))

    def test_restore_failure_is_visible_but_mode_restore_still_runs(self):
        with local_proxy() as (url, state, _), tempfile.TemporaryDirectory() as directory:
            state['fail'] = 'A'
            with probe.Controller(url) as controller, self.assertRaisesRegex(RuntimeError, '恢复代理状态失败'):
                probe.collect(controller, url, ['G'], new_database(), Path(directory) / 'db.json',
                              ['http://echo.test/ip'])
            self.assertEqual(('rule', 'B'), (state['mode'], state['selected']))
