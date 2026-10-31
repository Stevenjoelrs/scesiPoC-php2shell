import unittest

from poc.lab import normalize_platform


class PlatformNormalizationTests(unittest.TestCase):
    def test_amd64_alias(self):
        self.assertEqual(normalize_platform("linux/x86_64"), "linux/amd64")
        self.assertEqual(normalize_platform("linux/amd64"), "linux/amd64")

    def test_arm64_alias(self):
        self.assertEqual(normalize_platform("linux/aarch64"), "linux/arm64")
        self.assertEqual(normalize_platform("linux/arm64"), "linux/arm64")


if __name__ == "__main__":
    unittest.main()
