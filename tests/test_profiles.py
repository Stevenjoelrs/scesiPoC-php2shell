import unittest

from poc.config import project_root
from poc.profiles import (
    Profile,
    ProfileError,
    list_profiles,
    load_profile,
)


class ProfileTests(unittest.TestCase):
    def test_builtin_profiles_exist(self):
        names = list_profiles()
        self.assertIn("bookworm", names)
        self.assertIn("lab", names)

    def test_bookworm_values(self):
        profile = load_profile("bookworm")
        self.assertEqual(profile.zif_offset, 0x465370)
        self.assertEqual(profile.dtor_offset, 0x65EB60)
        self.assertEqual(profile.htdata_offset, 0x690D8)
        self.assertEqual(profile.stage1_n, 841)
        self.assertEqual(profile.stage2_t, 406)
        self.assertEqual(profile.stage2_v, 16)
        self.assertEqual(len(profile.stage3_pads), 6)
        self.assertTrue(profile.stage3_carrier)
        self.assertTrue(profile.stage3_cookie)

    def test_lab_values(self):
        profile = load_profile("lab")
        self.assertEqual(profile.stage3_pads[0], (8, 7))
        self.assertFalse(profile.stage3_carrier)
        self.assertFalse(profile.stage3_cookie)

    def test_load_by_path(self):
        path = project_root() / "profiles" / "bookworm.json"
        self.assertEqual(load_profile(str(path)).name, "bookworm")

    def test_fingerprint_is_stable(self):
        first = load_profile("bookworm").fingerprint()
        second = load_profile("bookworm").fingerprint()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_roundtrip(self):
        profile = load_profile("bookworm")
        self.assertEqual(Profile.from_dict(profile.to_dict()), profile)

    def test_with_offsets(self):
        profile = load_profile("bookworm").with_offsets(zif_offset=0x10, dtor_offset=0x20)
        self.assertEqual(profile.zif_offset, 0x10)
        self.assertEqual(profile.dtor_offset, 0x20)
        self.assertEqual(profile.stage1_n, 841)

    def test_unknown_profile(self):
        with self.assertRaises(ProfileError):
            load_profile("does-not-exist")

    def test_invalid_profiles(self):
        data = load_profile("bookworm").to_dict()
        data["stage3_pads"] = []
        with self.assertRaises(ProfileError):
            Profile.from_dict(data)

        data = load_profile("bookworm").to_dict()
        data["stage2_t"] = 999
        with self.assertRaises(ProfileError):
            Profile.from_dict(data)

        data = load_profile("bookworm").to_dict()
        data["name"] = "Bad Name"
        with self.assertRaises(ProfileError):
            Profile.from_dict(data)


if __name__ == "__main__":
    unittest.main()
