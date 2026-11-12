import json
import tempfile
import unittest
from pathlib import Path

from common import exit_report as report


class ExitReportTest(unittest.TestCase):
    def test_nodes_sharing_ip_remain_separate_and_old_nodes_survive(self):
        db = report.new_database()
        report.merge_observation(db, '旧节点', ['组一'], 'echo', '8.8.8.8', 't1')
        report.merge_observation(db, '新节点', ['组二'], 'echo', '8.8.8.8', 't2')
        self.assertEqual({'旧节点', '新节点'}, set(db['nodes']))
        self.assertEqual('t1', db['nodes']['旧节点']['first_seen'])

    def test_changed_ip_keeps_history_and_failure_keeps_success(self):
        db = report.new_database()
        report.merge_observation(db, 'A', ['G'], 'echo', '8.8.8.8', 't1')
        report.merge_observation(db, 'A', ['H'], 'echo', '1.1.1.1', 't2')
        report.merge_observation(db, 'A', ['H'], 'echo', None, 't3', error='timeout')
        node = db['nodes']['A']
        self.assertEqual('1.1.1.1', node['current']['echo']['ip'])
        self.assertEqual('t2', node['current']['echo']['observed_at'])
        self.assertEqual(['G', 'H'], node['groups'])
        self.assertEqual(3, len(node['observations']))
        self.assertEqual('error', node['last_attempts']['echo']['status'])

    def test_conflicts_unknown_residential_and_no_old_ip_rating(self):
        db = report.new_database()
        report.merge_observation(db, 'A', ['G'], 'echo', '8.8.8.8', 't1')
        db['ip_cache']['8.8.8.8'] = {'sources': {
            'ip-api': {'data': {'hosting': True, 'countryCode': 'US'}},
            'ipapi.is': {'data': {'is_datacenter': False, 'location': {'country_code': 'JP'},
                                 'company': {'type': 'isp'}}},
        }}
        summary = report.summarize(db, db['nodes']['A'])['8.8.8.8']['fields']
        self.assertTrue(summary['hosting']['conflict'])
        self.assertIsNone(summary['hosting']['value'])
        self.assertIsNone(summary['residential']['value'])
        self.assertIsNone(summary['proxy']['value'])
        report.merge_observation(db, 'A', ['G'], 'echo', '1.1.1.1', 't2')
        self.assertNotIn('8.8.8.8', report.summarize(db, db['nodes']['A']))

    def test_database_roundtrip_corruption_and_exclusive_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'db.json'
            with report.database_lock(path):
                db = report.load_database(path)
                report.merge_observation(db, 'A', ['G'], 'echo', '8.8.8.8', 't')
                report.save_database(path, db)
                with self.assertRaises(RuntimeError):
                    with report.database_lock(path):
                        pass
            self.assertEqual('8.8.8.8', report.load_database(path)['nodes']['A']['current']['echo']['ip'])
            path.write_text('{broken')
            with self.assertRaises(ValueError):
                report.load_database(path)
            self.assertEqual('{broken', path.read_text())
            path.write_text(json.dumps({'schema_version': 999, 'nodes': {}, 'ip_cache': {}}))
            with self.assertRaises(ValueError):
                report.load_database(path)

    def test_vpn_provider_value_is_positive_evidence_not_false(self):
        db = report.new_database()
        report.merge_observation(db, 'VPN', ['G'], 'echo', '8.8.8.8', 't')
        db['ip_cache']['8.8.8.8'] = {'sources': {
            'ip-api': {'data': {'proxy': False}},
            'ipapi.is': {'data': {'is_proxy': False, 'is_vpn': 'NordVPN', 'is_tor': False}},
        }}
        fields = report.summarize(db, db['nodes']['VPN'])['8.8.8.8']['fields']
        self.assertIs(True, fields['vpn']['value'])
        self.assertTrue(fields['proxy']['conflict'])
        self.assertIsNone(fields['proxy']['value'])

    def test_different_echo_services_keep_separate_current_exits(self):
        db = report.new_database()
        report.merge_observation(db, 'A', ['G'], 'echo-1', '8.8.8.8', 't1')
        report.merge_observation(db, 'A', ['G'], 'echo-2', '1.1.1.1', 't2')
        self.assertEqual({'8.8.8.8', '1.1.1.1'}, set(report.summarize(db, db['nodes']['A'])))
