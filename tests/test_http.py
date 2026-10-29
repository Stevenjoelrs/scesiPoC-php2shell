import gzip
import unittest

from poc.http import HttpResponse, parse_response


class ParseResponseTests(unittest.TestCase):
    def test_basic_headers_and_cookie(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 2\r\n"
            b"X-Powered-By: PHP/8.4.26\r\n"
            b"Set-Cookie: PHPSESSID=abc; path=/\r\n"
            b"\r\nOK"
        )
        response = parse_response(raw)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, "OK")
        self.assertEqual(response.header("x-powered-by"), "PHP/8.4.26")
        self.assertEqual(response.cookie("PHPSESSID"), "abc")
        self.assertEqual(response.body, b"OK")

    def test_multiple_set_cookie_headers(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Set-Cookie: a=1\r\n"
            b"Set-Cookie: b=2\r\n"
            b"\r\n"
        )
        response = parse_response(raw)
        self.assertEqual(response.set_cookies, ("a=1", "b=2"))
        self.assertEqual(response.cookie("b"), "2")

    def test_chunked_body(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        )
        self.assertEqual(parse_response(raw).body, b"Wikipedia")

    def test_content_length_truncates(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOKEXTRA"
        self.assertEqual(parse_response(raw).body, b"OK")

    def test_gzip_body(self):
        payload = gzip.compress(b"hello")
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
            + b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
        )
        self.assertEqual(parse_response(raw).body, b"hello")

    def test_truncated_response(self):
        self.assertEqual(parse_response(b"").status, 0)
        self.assertEqual(parse_response(b"HTTP/1.1 200 OK\r\n").status, 0)

    def test_header_lookup_is_case_insensitive(self):
        response = HttpResponse(status=200, headers={"x-test": "1"})
        self.assertEqual(response.header("X-Test"), "1")


if __name__ == "__main__":
    unittest.main()
