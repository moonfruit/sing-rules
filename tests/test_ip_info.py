import csv
import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from common import ip_info
from common.exit_report import export_csv, merge_observation, new_database


@contextmanager
def databases():
    state = {'calls': [], 'rate_limit': False, 'wrong_ip': False, 'bad_key': False,
             'nullable': False, 'anonymous': False, 'batches': [], 'fail_ip': None}

    def api_data(ip):
        if ip == state['fail_ip']:
            return {'status': 'fail', 'query': ip, 'message': 'invalid query'}
        return {'status': 'success', 'query': '1.1.1.1' if state['wrong_ip'] else ip,
                'countryCode': 'US', 'regionName': 'California', 'city': 'Mountain View',
                'isp': 'Google', 'org': 'Google', 'as': 'AS15169 Google',
                'hosting': True, 'proxy': False, 'mobile': False}

    def ipapi_data(ip):
        if state['nullable']:
            return {'ip': ip, 'company': None, 'location': None,
                    'is_datacenter': True, 'is_proxy': False, 'is_vpn': True, 'is_tor': False}
        if state['anonymous']:
            return {'ip': ip, 'company': None, 'location': None}
        return {'ip': ip, 'is_datacenter': True, 'is_proxy': False, 'is_vpn': False,
                'is_tor': False, 'is_mobile': False,
                'company': {'name': 'Google', 'type': 'hosting'},
                'asn': {'asn': 15169, 'org': 'Google', 'type': 'hosting'},
                'location': {'country_code': 'US', 'state': 'California', 'city': 'Mountain View'}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, data, status=200):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            if status == 429:
                self.send_header('Retry-After', '3600')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            state['calls'].append('ip-api')
            if state['rate_limit']:
                self.reply({'status': 'fail'}, 429)
            else:
                self.reply({'status': 'success', 'query': '1.1.1.1' if state['wrong_ip'] else '8.8.8.8',
                            'countryCode': 'US', 'regionName': 'California', 'city': 'Mountain View',
                            'isp': 'Google', 'org': 'Google', 'as': 'AS15169 Google',
                            'hosting': True, 'proxy': False, 'mobile': False})

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if self.path.startswith('/batch'):
                state['calls'].append('ip-api')
                state['batches'].append(('ip-api', data))
                if not isinstance(data, list) or len(data) > 100:
                    self.reply({}, 422)
                elif state['rate_limit']:
                    self.reply({'status': 'fail'}, 429)
                else:
                    self.reply([api_data(ip) for ip in reversed(data)])
                return
            state['calls'].append('ipapi.is')
            if data.get('key') != 'test-secret':
                self.reply({'error': 'bad key'}, 403)
                return
            if state['bad_key']:
                self.reply({'error': 'test-secret'}, 403)
                return
            if 'ips' in data:
                state['batches'].append(('ipapi.is', data['ips']))
                if len(data['ips']) > 100:
                    self.reply({}, 400)
                    return
                self.reply({**{ip: ipapi_data(ip) for ip in reversed(data['ips']) if ip != state['fail_ip']},
                            'total_elapsed_ms': 0.42})
            else:
                self.reply(ipapi_data(data['q']))

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f'http://127.0.0.1:{server.server_port}'
        yield {'ip-api': base + '/json/{ip}', 'ip-api-batch': base + '/batch',
               'ipapi.is': base + '/lookup'}, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class IPInfoTest(unittest.TestCase):
    def make_database(self):
        db = new_database()
        for name in ['节点 A', '节点 B']:
            merge_observation(db, name, ['G'], 'echo', '8.8.8.8', 't')
        return db

    def test_cache_deduplicates_nodes_and_csv_exposes_network_fields(self):
        with databases() as (endpoints, state), tempfile.TemporaryDirectory() as directory:
            db = self.make_database()
            path = Path(directory) / 'db.json'
            with ip_info.LookupClient('test-secret', endpoints=endpoints) as client:
                self.assertEqual(0, ip_info.enrich(db, path, client))
                self.assertEqual(0, ip_info.enrich(db, path, client))
            self.assertEqual(['ip-api', 'ipapi.is'], state['calls'])
            self.assertNotIn('test-secret', path.read_text())
            output = io.StringIO()
            export_csv(db, output)
            rows = list(csv.DictReader(io.StringIO(output.getvalue())))
            self.assertEqual(['节点 A', '节点 B'], [row['node'] for row in rows])
            self.assertEqual('True', rows[0]['hosting'])
            self.assertEqual('False', rows[0]['proxy'])
            self.assertEqual('unknown', rows[0]['residential'])
            self.assertEqual('US', rows[0]['country_code'])
            self.assertIn('ipapi.is', json.loads(rows[0]['query_times']))
            self.assertEqual('t', rows[0]['probe_attempted_at'])

    def test_refresh_failure_keeps_data_and_stops_rate_limited_source(self):
        with databases() as (endpoints, state), tempfile.TemporaryDirectory() as directory:
            db = self.make_database()
            path = Path(directory) / 'db.json'
            with ip_info.LookupClient('test-secret', endpoints=endpoints) as client:
                ip_info.enrich(db, path, client)
                state['rate_limit'] = True
                state['bad_key'] = True
                self.assertEqual(2, ip_info.enrich(db, path, client, refresh=True))
            entry = db['ip_cache']['8.8.8.8']['sources']['ip-api']
            self.assertEqual('US', entry['data']['countryCode'])
            self.assertIn('429', entry['error'])
            self.assertNotIn('test-secret', path.read_text())
            calls = len(state['calls'])
            with ip_info.LookupClient('test-secret', endpoints=endpoints) as client:
                ip_info.enrich(db, path, client, refresh=True)
            self.assertEqual(calls, len(state['calls']))

    def test_mismatched_ip_is_not_accepted_as_success(self):
        with databases() as (endpoints, state), tempfile.TemporaryDirectory() as directory:
            state['wrong_ip'] = True
            db = self.make_database()
            with ip_info.LookupClient(None, endpoints=endpoints) as client:
                self.assertGreater(ip_info.enrich(db, Path(directory) / 'db.json', client), 0)
            self.assertNotIn('data', db['ip_cache']['8.8.8.8']['sources']['ip-api'])

    def test_query_an_explicit_ip_does_not_create_a_node(self):
        with databases() as (endpoints, _), tempfile.TemporaryDirectory() as directory:
            db = new_database()
            with ip_info.LookupClient('test-secret', endpoints=endpoints) as client:
                ip_info.enrich(db, Path(directory) / 'db.json', client, ips=['8.8.8.8'])
            self.assertEqual({}, db['nodes'])
            self.assertIn('data', db['ip_cache']['8.8.8.8']['sources']['ipapi.is'])

    def test_nullable_ownership_keeps_flags_but_anonymous_response_is_rejected(self):
        with databases() as (endpoints, state):
            with ip_info.LookupClient('test-secret', endpoints=endpoints) as client:
                state['nullable'] = True
                data = client.lookup('ipapi.is', '8.8.8.8', {})
                from common.exit_report import source_fields
                fields = source_fields('ipapi.is', data)
                self.assertIsNone(fields['country_code'])
                self.assertTrue(fields['hosting'])
                self.assertTrue(fields['proxy'])
                state['nullable'] = False
                state['anonymous'] = True
                with self.assertRaises(RuntimeError):
                    client.lookup('ipapi.is', '8.8.8.8', {})

    def test_enrich_batches_101_ips_and_maps_reordered_responses(self):
        with databases() as (endpoints, state), tempfile.TemporaryDirectory() as directory:
            db = new_database()
            ips = [f'8.8.4.{i}' for i in range(1, 102)]
            with ip_info.LookupClient('test-secret', endpoints=endpoints) as client:
                self.assertEqual(0, ip_info.enrich(db, Path(directory) / 'db.json', client, ips=ips))
            self.assertEqual([('ip-api', 100), ('ip-api', 1), ('ipapi.is', 100), ('ipapi.is', 1)],
                             [(source, len(batch)) for source, batch in state['batches']])
            for ip in ips:
                self.assertEqual(ip, db['ip_cache'][ip]['sources']['ip-api']['data']['query'])
                self.assertEqual(ip, db['ip_cache'][ip]['sources']['ipapi.is']['data']['ip'])

    def test_batch_partial_failures_do_not_drop_other_successes(self):
        with databases() as (endpoints, state), tempfile.TemporaryDirectory() as directory:
            state['fail_ip'] = '1.1.1.1'
            db = new_database()
            with ip_info.LookupClient('test-secret', endpoints=endpoints) as client:
                self.assertEqual(2, ip_info.enrich(db, Path(directory) / 'db.json', client,
                                                 ips=['8.8.8.8', '1.1.1.1']))
            for source in ['ip-api', 'ipapi.is']:
                self.assertIn('data', db['ip_cache']['8.8.8.8']['sources'][source])
                self.assertNotIn('data', db['ip_cache']['1.1.1.1']['sources'][source])
                self.assertIn('error', db['ip_cache']['1.1.1.1']['sources'][source])

    def test_environment_controls_lookup_proxy(self):
        with databases() as (endpoints, state):
            proxy = endpoints['ipapi.is'].removesuffix('/lookup')
            with patch.dict(os.environ, {'http_proxy': proxy, 'HTTP_PROXY': proxy,
                                         'no_proxy': '', 'NO_PROXY': ''}):
                with ip_info.LookupClient('test-secret', timeout=2,
                                          endpoints={'ipapi.is': 'http://lookup.invalid/lookup'}) as client:
                    result = client.lookup_batch('ipapi.is', ['8.8.8.8'], {})
            self.assertEqual('8.8.8.8', result['8.8.8.8']['data']['ip'])
            self.assertEqual(['ipapi.is'], state['calls'])
