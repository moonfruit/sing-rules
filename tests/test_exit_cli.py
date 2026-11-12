import contextlib
import csv
import io
import os
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common import ip_info
from common.exit_report import load_database, merge_observation, new_database, save_database
from tests.test_exit_probe import local_proxy
from tests.test_ip_info import databases


cli = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'probe-exits.py'))


class ExitCLITest(unittest.TestCase):
    def test_collect_enrich_export_preserves_old_nodes_and_restores_proxy(self):
        with tempfile.TemporaryDirectory() as directory, local_proxy() as (url, state, proxies):
            proxies['Nested']['all'] = ['A']
            path = Path(directory) / 'db.json'
            db = new_database()
            merge_observation(db, '旧节点', ['旧分组'], 'old', '8.8.8.8', 't0')
            save_database(path, db)
            self.assertEqual(0, cli['main'](['collect', '--database', str(path), '--group', 'Nest',
                                             '--api', url, '--proxy', url, '--echo-url', 'http://echo.test/ip']))
            self.assertEqual(('rule', 'A'), (state['mode'], state['selected']))
            with databases() as (endpoints, calls), patch.dict(ip_info.ENDPOINTS, endpoints), \
                    patch.dict(os.environ, {'IPAPI_IS_KEY': 'test-secret'}):
                self.assertEqual(0, cli['main'](['enrich', '--database', str(path)]))
            self.assertEqual(['ip-api', 'ipapi.is'], calls['calls'])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, cli['main'](['export', '--database', str(path)]))
            rows = list(csv.DictReader(io.StringIO(output.getvalue())))
            self.assertEqual({'旧节点', 'A'}, {row['node'] for row in rows})
            self.assertEqual({'US'}, {row['country_code'] for row in rows})
            self.assertEqual({'旧节点', 'A'}, set(load_database(path)['nodes']))

    def test_export_cannot_overwrite_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'db.json'
            save_database(path, new_database())
            original = path.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, cli['main'](['export', '--database', str(path), '--output', str(path)]))
            self.assertEqual(original, path.read_bytes())
