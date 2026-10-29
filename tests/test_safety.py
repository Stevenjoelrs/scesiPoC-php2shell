import unittest

from poc.safety import (
    ScopeError,
    assert_in_scope,
    classify,
    describe_target,
    resolve,
)


class ClassifyTests(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(classify("127.0.0.1"), "loopback")
        self.assertEqual(classify("::1"), "loopback")
        self.assertEqual(classify("10.0.0.5"), "private")
        self.assertEqual(classify("192.168.1.1"), "private")
        self.assertEqual(classify("169.254.1.1"), "link-local")
        self.assertEqual(classify("224.0.0.1"), "multicast")
        self.assertEqual(classify("8.8.8.8"), "public")
        self.assertEqual(classify("not-an-ip"), "invalid")

    def test_zone_is_ignored(self):
        self.assertEqual(classify("fe80::1%en0"), "link-local")


class ScopeTests(unittest.TestCase):
    def test_loopback_and_private_are_allowed(self):
        self.assertEqual(assert_in_scope("127.0.0.1", 8088).primary, "127.0.0.1")
        assert_in_scope("10.1.2.3", 8088)
        assert_in_scope("::1", 8088)

    def test_public_is_refused_by_default(self):
        with self.assertRaises(ScopeError):
            assert_in_scope("8.8.8.8", 443)

    def test_public_can_be_overridden(self):
        resolution = assert_in_scope("8.8.8.8", 443, allow_public=True)
        self.assertEqual(resolution.primary, "8.8.8.8")

    def test_explicit_allowlist(self):
        resolution = assert_in_scope("8.8.8.8", 443, allow_hosts=("8.8.8.8",))
        self.assertEqual(resolution.primary, "8.8.8.8")

    def test_multicast_and_unspecified_are_refused(self):
        with self.assertRaises(ScopeError):
            assert_in_scope("224.0.0.1", 80)
        with self.assertRaises(ScopeError):
            assert_in_scope("0.0.0.0", 80)

    def test_bad_port(self):
        with self.assertRaises(ScopeError):
            resolve("127.0.0.1", 0)

    def test_ipv4_is_preferred(self):
        resolution = resolve("127.0.0.1", 80)
        self.assertFalse(":" in resolution.primary)
        self.assertTrue(resolution.is_loopback)

    def test_description_contains_class(self):
        text = describe_target("127.0.0.1", 8088)
        self.assertIn("loopback", text)


if __name__ == "__main__":
    unittest.main()
