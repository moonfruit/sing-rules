import copy
import contextlib
import csv
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common import exit_report as report
from common import ip_info
from tests.test_exit_cli import cli
from tests.test_exit_probe import local_proxy
from tests.test_ip_info import databases


@unittest.skipUnless(shutil.which('sops') and shutil.which('age-keygen'), '需要 sops 和 age-keygen')
class SopsDatabaseTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.key = self.root / 'key.txt'
        subprocess.run(['age-keygen', '-o', str(self.key)], capture_output=True, check=True)
        recipient = subprocess.run(['age-keygen', '-y', str(self.key)], capture_output=True,
                                   text=True, check=True).stdout.strip()
        self.config = self.root / '.sops.yaml'
        self.config.write_text(f'creation_rules:\n  - path_regex: \\.sops\\.json$\n    age: {recipient}\n')
        self.addCleanup(patch.stopall)
        patch.object(report, 'SOPS_CONFIG', self.config).start()
        patch.dict(os.environ, {'SOPS_AGE_KEY_FILE': str(self.key), 'SOPS_AGE_KEY': ''}).start()
        self.path = self.root / 'exits.sops.json'

    def database(self):
        db = report.new_database()
        report.merge_observation(db, 'PRIVATE_NODE_SENTINEL_1234', ['private-group'], 'echo', '8.8.8.8', 't1')
        return db

    def test_real_sops_roundtrip_hides_node_names_and_ip_keys(self):
        db = self.database()
        report.save_database(self.path, db)
        cipher = self.path.read_text()
        self.assertEqual({'data', 'sops'}, set(json.loads(cipher)))
        self.assertNotIn('PRIVATE_NODE_SENTINEL_1234', cipher)
        self.assertNotIn('8.8.8.8', cipher)
        self.assertEqual(db, report.load_database(self.path))
        self.assertEqual({'key.txt', '.sops.yaml', 'exits.sops.json'}, {p.name for p in self.root.iterdir()})

    def test_incremental_update_keeps_old_nodes_and_unchanged_save_keeps_cipher(self):
        db = self.database()
        report.save_database(self.path, db)
        original = self.path.read_bytes()
        db = report.load_database(self.path)
        report.save_database(self.path, db)
        self.assertEqual(original, self.path.read_bytes())
        report.merge_observation(db, 'new-node', ['new-group'], 'echo', '1.1.1.1', 't2')
        report.save_database(self.path, db)
        self.assertEqual({'PRIVATE_NODE_SENTINEL_1234', 'new-node'}, set(report.load_database(self.path)['nodes']))

    def test_encrypt_failure_does_not_replace_old_cipher_or_leave_plaintext(self):
        db = self.database()
        report.save_database(self.path, db)
        original = self.path.read_bytes()
        report.merge_observation(db, 'new-node', ['G'], 'echo', '1.1.1.1', 't2')
        self.config.write_text('creation_rules: []\n')
        with self.assertRaises(RuntimeError):
            report.save_database(self.path, db)
        self.assertEqual(original, self.path.read_bytes())
        self.assertEqual({'key.txt', '.sops.yaml', 'exits.sops.json'}, {p.name for p in self.root.iterdir()})

    def test_wrong_key_and_tampered_cipher_are_not_loaded(self):
        report.save_database(self.path, self.database())
        original = self.path.read_bytes()
        wrong_key = self.root / 'wrong-key.txt'
        subprocess.run(['age-keygen', '-o', str(wrong_key)], capture_output=True, check=True)
        with patch.dict(os.environ, {'SOPS_AGE_KEY_FILE': str(wrong_key)}), self.assertRaises(RuntimeError):
            report.load_database(self.path)
        self.assertEqual(original, self.path.read_bytes())
        damaged = json.loads(original)
        damaged['data'] = damaged['data'].replace('data:', 'data:A', 1)
        self.path.write_text(json.dumps(damaged))
        with self.assertRaises(RuntimeError):
            report.load_database(self.path)

    def test_sops_suffix_rejects_plaintext_and_plain_json_remains_supported(self):
        db = self.database()
        self.path.write_text(json.dumps(db))
        with self.assertRaises(ValueError):
            report.load_database(self.path)
        plain = self.root / 'legacy.json'
        expected = copy.deepcopy(db)
        report.save_database(plain, expected)
        self.assertEqual(expected, report.load_database(plain))

    def test_cli_collect_enrich_and_export_work_directly_on_cipher(self):
        with local_proxy() as (url, state, _):
            self.assertEqual(0, cli['main'](['collect', '--database', str(self.path), '--group', 'Nest',
                                             '--api', url, '--proxy', url, '--echo-url', 'http://echo.test/ip']))
            self.assertEqual(('rule', 'A'), (state['mode'], state['selected']))
        with databases() as (endpoints, _), patch.dict(ip_info.ENDPOINTS, endpoints), \
                patch.dict(os.environ, {'IPAPI_IS_KEY': 'test-secret'}):
            self.assertEqual(0, cli['main'](['enrich', '--database', str(self.path)]))
        self.assertEqual({'data', 'sops'}, set(json.loads(self.path.read_text())))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, cli['main'](['export', '--database', str(self.path)]))
        rows = list(csv.DictReader(io.StringIO(output.getvalue())))
        self.assertEqual({'A', 'B'}, {row['node'] for row in rows})
        self.assertEqual({'US'}, {row['country_code'] for row in rows})
