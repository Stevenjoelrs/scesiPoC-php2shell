import struct
import tempfile
import unittest
from pathlib import Path

from poc.offsets import (
    LibphpOffsets,
    OffsetsError,
    offsets_from_env,
    parse_libphp,
    parse_libphp_bytes,
    read_env,
    write_env,
)


def _align(value, alignment=8):
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf(symbols, bias=0x1000):
    """Build a minimal little-endian ELF64 with .symtab/.strtab."""
    strtab = bytearray(b"\x00")
    names = []
    for name, _offset in symbols:
        names.append(len(strtab))
        strtab += name.encode("ascii") + b"\x00"

    symtab = bytearray(24)  # null symbol
    for (name, offset), name_offset in zip(symbols, names):
        symtab += struct.pack("<IBBHQQ", name_offset, 0x12, 0, 1, bias + offset, 0)

    strtab_offset = 64 + 56
    symtab_offset = _align(strtab_offset + len(strtab))
    shoff = _align(symtab_offset + len(symtab))

    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, shoff, 0, 64, 56, 1, 64, 3, 0
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, bias, bias, 0x100, 0x100, 0x1000)
    sh_null = b"\x00" * 64
    sh_str = struct.pack(
        "<IIQQQQIIQQ", 0, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0
    )
    sh_sym = struct.pack(
        "<IIQQQQIIQQ", 0, 2, 0, 0, symtab_offset, len(symtab), 1, 1, 8, 24
    )

    image = bytearray(ehdr + phdr)
    image += strtab
    image += b"\x00" * (symtab_offset - len(image))
    image += symtab
    image += b"\x00" * (shoff - len(image))
    image += sh_null + sh_str + sh_sym
    if len(image) < 0x6000:
        image += b"\x00" * (0x6000 - len(image))
    return bytes(image)


class ElfParserTests(unittest.TestCase):
    def test_parse_symbols(self):
        raw = build_elf([("zif_system", 0x1234), ("zval_ptr_dtor", 0x5678)])
        bias, symbols = parse_libphp_bytes(raw)
        self.assertEqual(bias, 0x1000)
        self.assertEqual(symbols["zif_system"], 0x2234)
        self.assertEqual(symbols["zval_ptr_dtor"], 0x6678)

    def test_parse_file_returns_relative_offsets(self):
        raw = build_elf([("zif_system", 0x1234), ("zval_ptr_dtor", 0x5678)])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "libphp.so"
            path.write_bytes(raw)
            offsets = parse_libphp(path)
        self.assertEqual(offsets.zif_system, 0x1234)
        self.assertEqual(offsets.zval_ptr_dtor, 0x5678)
        self.assertEqual(len(offsets.sha256), 64)

    def test_missing_symbol(self):
        raw = build_elf([("zif_system", 0x1234)])
        with self.assertRaises(OffsetsError):
            parse_libphp_bytes(raw)

    def test_bad_magic(self):
        with self.assertRaises(OffsetsError):
            parse_libphp_bytes(b"not an elf" + b"\x00" * 100)


class OffsetsEnvTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "offsets.env"
            info = LibphpOffsets(0x465370, 0x65EB60, "abc", "php2shell-vuln")
            write_env(path, info)
            loaded = offsets_from_env(path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.zif_system, 0x465370)
        self.assertEqual(loaded.zval_ptr_dtor, 0x65EB60)
        self.assertEqual(loaded.sha256, "abc")
        self.assertEqual(loaded.container, "php2shell-vuln")

    def test_missing_file(self):
        self.assertEqual(read_env(Path("/nonexistent/offsets.env")), {})
        self.assertIsNone(offsets_from_env(Path("/nonexistent/offsets.env")))

    def test_invalid_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "offsets.env"
            path.write_text("ZIF_OFFSET=nope\nDTOR_OFFSET=0x1\n", encoding="utf-8")
            with self.assertRaises(OffsetsError):
                offsets_from_env(path)


if __name__ == "__main__":
    unittest.main()
