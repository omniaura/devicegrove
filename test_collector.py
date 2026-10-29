import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import collector


class CollectorTests(unittest.TestCase):
    def test_filevault_only_unambiguous_values_decide(self):
        for rows, expected in [
            ([{"filevault_status": "on"}], "unknown"),
            ([{"filevault_status": "off"}], "fail"),
            ([{"filevault_status": "on"}, {"filevault_status": "off"}], "unknown"),
            ([{"filevault_status": "unknown"}], "unknown"),
            ([{"filevault_status": []}], "unknown"),
            ([], "unknown"), (None, "unknown"),
        ]:
            with self.subTest(rows=rows):
                self.assertEqual(collector.evaluate({"filevault": rows})["filevault"]["status"], expected)

    def test_other_controls_never_pass_on_partial_evidence(self):
        checks = collector.evaluate({"screen_lock": [{"enabled": "1", "grace_period": "0"}], "os_version": [{"version": "15.1", "build": "24B83"}]})
        for name in ("screen_lock", "os_updates", "endpoint_protection", "password_manager"):
            self.assertEqual(checks[name]["status"], "unknown")
        self.assertEqual(checks["screen_lock"]["evidence"]["grace_seconds"], 0)

    def test_untrusted_fields_are_not_exported(self):
        data = {"filevault": [{"filevault_status": "on", "uuid": "secret"}], "os_version": [{"version": "15.1", "build": "24B83", "username": "secret"}], "screen_lock": [{"enabled": "1", "grace_period": "0", "home": "secret"}]}
        self.assertNotIn("secret", json.dumps(collector.evaluate(data)))

    def test_bad_query_output_and_errors_are_unknown(self):
        with patch.object(collector.subprocess, "run", side_effect=OSError("private path")):
            evidence = collector.collect("/missing")
        self.assertTrue(all(c["status"] == "unknown" for c in evidence["checks"].values()))
        self.assertNotIn("private path", json.dumps(evidence))

    def test_query_contract_and_invalid_json(self):
        class Response:
            returncode = 0
            stdout = b"not-json"
        with patch.object(collector.subprocess, "run", return_value=Response()) as run:
            self.assertIsNone(collector.query("/osqueryi", collector.QUERIES["filevault"]))
        self.assertEqual(run.call_args.args[0][-1], collector.QUERIES["filevault"])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_subprocess_collector_with_fake_osquery(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "osqueryi"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "q = sys.argv[-1]\n"
                "rows = ([{'filevault_status': 'off', 'uuid': 'private'}] "
                "if 'disk_encryption' in q else "
                "[{'enabled': '1', 'grace_period': '0'}] if 'screenlock' in q "
                "else [{'version': '15.1', 'build': '24B83'}])\n"
                "print(json.dumps(rows))\n"
            )
            os.chmod(binary, 0o700)
            evidence = collector.collect(str(binary))
        self.assertEqual(evidence["checks"]["filevault"]["status"], "fail")
        self.assertEqual(evidence["checks"]["os_updates"]["evidence"]["version"], "15.1")
        self.assertNotIn("private", json.dumps(evidence))


if __name__ == "__main__":
    unittest.main()
