import unittest

from poc.detect import (
    INCONCLUSIVE,
    PATCHED,
    UNKNOWN,
    VULNERABLE,
    Detection,
    assess_version,
    parse_php_version,
    probe_verdict,
    version_text,
)


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_php_version("PHP/8.4.26"), (8, 4, 26))
        self.assertEqual(parse_php_version("PHP/8.4.27 (cli)"), (8, 4, 27))
        self.assertIsNone(parse_php_version(""))
        self.assertIsNone(parse_php_version("php/8.4.26"))

    def test_text(self):
        self.assertEqual(version_text((8, 4, 26)), "8.4.26")
        self.assertEqual(version_text(None), "unknown")

    def test_assessment(self):
        self.assertEqual(assess_version((8, 4, 26)), VULNERABLE)
        self.assertEqual(assess_version((8, 4, 27)), PATCHED)
        self.assertEqual(assess_version((8, 4, 30)), PATCHED)
        self.assertEqual(assess_version((8, 3, 35)), VULNERABLE)
        self.assertEqual(assess_version((8, 3, 36)), PATCHED)
        self.assertEqual(assess_version((8, 5, 11)), VULNERABLE)
        self.assertEqual(assess_version((8, 5, 12)), PATCHED)
        self.assertEqual(assess_version((8, 1, 0)), UNKNOWN)
        self.assertEqual(assess_version(None), UNKNOWN)


class ProbeVerdictTests(unittest.TestCase):
    def test_leak_wins(self):
        self.assertEqual(probe_verdict(UNKNOWN, True, 4096), VULNERABLE)

    def test_patched_requires_no_leak(self):
        self.assertEqual(probe_verdict(PATCHED, False, 32), PATCHED)

    def test_vulnerable_banner_but_no_leak_is_inconclusive(self):
        self.assertEqual(probe_verdict(VULNERABLE, False, 32), INCONCLUSIVE)

    def test_banner_only(self):
        self.assertEqual(probe_verdict(VULNERABLE, False, 0), INCONCLUSIVE)


class DetectionSerializationTests(unittest.TestCase):
    def test_to_dict(self):
        detection = Detection(
            url="http://127.0.0.1:8088/index.php",
            status_code=200,
            powered_by="PHP/8.4.26",
            version=(8, 4, 26),
            verdict=VULNERABLE,
        )
        payload = detection.to_dict()
        self.assertEqual(payload["version"], "8.4.26")
        self.assertEqual(payload["verdict"], VULNERABLE)
        self.assertNotIn("probe", payload)


if __name__ == "__main__":
    unittest.main()
