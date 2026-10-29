import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from poc.config import (
    ConfigError,
    ExploitConfig,
    LabConfig,
    TargetConfig,
    parse_env_file,
)


class EnvFileTests(unittest.TestCase):
    def test_parses_comments_quotes_and_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(
                "# comment\n"
                "VULN_PORT=8088\n"
                "export FOO=\"bar baz\"\n"
                "QUOTED='x'\n"
                "EMPTY=\n",
                encoding="utf-8",
            )
            values = parse_env_file(path)
        self.assertEqual(values["VULN_PORT"], "8088")
        self.assertEqual(values["FOO"], "bar baz")
        self.assertEqual(values["QUOTED"], "x")
        self.assertEqual(values["EMPTY"], "")

    def test_missing_file_is_empty(self):
        self.assertEqual(parse_env_file(Path("/nonexistent/.env")), {})


class TargetConfigTests(unittest.TestCase):
    def test_defaults(self):
        target = TargetConfig("http://127.0.0.1:8088/index.php")
        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 8088)
        self.assertEqual(target.path, "/index.php")
        self.assertEqual(target.host_header, "127.0.0.1:8088")

    def test_default_ports_are_not_echoed(self):
        self.assertEqual(TargetConfig("http://example.com/").host_header, "example.com")
        self.assertEqual(TargetConfig("https://example.com/").host_header, "example.com")

    def test_query_is_preserved(self):
        self.assertEqual(TargetConfig("http://127.0.0.1/x?a=1").path, "/x?a=1")
        self.assertEqual(TargetConfig("http://127.0.0.1").path, "/")

    def test_ipv6_host_header(self):
        target = TargetConfig("http://[::1]:8080/x")
        self.assertEqual(target.host, "::1")
        self.assertEqual(target.host_header, "[::1]:8080")

    def test_rejects_bad_scheme_and_credentials(self):
        with self.assertRaises(ConfigError):
            TargetConfig("ftp://127.0.0.1/")
        with self.assertRaises(ConfigError):
            TargetConfig("http://user:pass@127.0.0.1/")
        with self.assertRaises(ConfigError):
            TargetConfig("http://127.0.0.1:99999/")


class ExploitConfigTests(unittest.TestCase):
    def test_defaults_are_valid(self):
        ExploitConfig().validate()

    def test_command_limit(self):
        with self.assertRaises(ConfigError):
            ExploitConfig(cmd="x" * 15).validate()
        ExploitConfig(cmd="cat /f>/out/p1").validate()  # exactly 14

    def test_ranges(self):
        with self.assertRaises(ConfigError):
            ExploitConfig(huge_mb=8).validate()
        with self.assertRaises(ConfigError):
            ExploitConfig(retries=0).validate()


class LabConfigTests(unittest.TestCase):
    def test_env_file_and_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(
                "VULN_PORT=18088\nPATCHED_PORT=18089\n"
                "VULN_IMAGE=php:test-vuln\nPATCHED_IMAGE=php:test-patched\n",
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                lab = LabConfig.from_env(root)
                self.assertEqual(lab.vuln_port, 18088)
                self.assertEqual(lab.patched_port, 18089)
                self.assertEqual(lab.vuln_image, "php:test-vuln")
                self.assertEqual(lab.vuln_url, "http://127.0.0.1:18088/index.php")

            with mock.patch.dict(os.environ, {"VULN_PORT": "19000"}, clear=True):
                lab = LabConfig.from_env(root)
                self.assertEqual(lab.vuln_port, 19000)

    def test_runtime_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lab = LabConfig(root=root, compose_file=root / "c.yml", env_file=root / ".env")
        self.assertEqual(lab.vuln_out, root / "runtime" / "out")
        self.assertEqual(lab.patched_out, root / "runtime" / "patched" / "out")
        self.assertEqual(lab.flag_file, root / "runtime" / "f")


if __name__ == "__main__":
    unittest.main()
