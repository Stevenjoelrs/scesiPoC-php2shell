import unittest

from poc.multipart import build_multipart, field, file_part, session_parts


class MultipartTests(unittest.TestCase):
    def test_field_bytes_are_exact(self):
        data = build_multipart([field("a", b"V")], b"B")
        self.assertEqual(
            data,
            b'--B\r\nContent-Disposition: form-data; name="a"\r\n\r\nV\r\n--B--\r\n',
        )

    def test_file_part(self):
        data = build_multipart([file_part("f", "a.txt", b"A")], b"B")
        self.assertIn(b'; filename="a.txt"', data)
        self.assertIn(b"Content-Type: application/octet-stream", data)

    def test_str_data_is_encoded(self):
        self.assertEqual(field("a", "hola").data, b"hola")

    def test_rejects_empty_or_unsafe_tokens(self):
        with self.assertRaises(ValueError):
            build_multipart([field("", b"x")], b"B")
        with self.assertRaises(ValueError):
            build_multipart([field('a"b', b"x")], b"B")
        with self.assertRaises(ValueError):
            build_multipart([field("a", b"x")], b"")
        with self.assertRaises(ValueError):
            build_multipart([field("a", b"x")], b"B" * 71)
        with self.assertRaises(ValueError):
            build_multipart([field("a", b"x")], b"B\r\nX")

    def test_session_parts_order(self):
        parts = session_parts(b"\x00")
        self.assertEqual([part.name for part in parts], ["PHPSESSID", "PHP_SESSION_UPLOAD_PROGRESS"])
        self.assertEqual(parts[0].data, b"\x00")


if __name__ == "__main__":
    unittest.main()
