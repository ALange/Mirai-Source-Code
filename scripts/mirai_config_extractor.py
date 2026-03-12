#!/usr/bin/env python3
"""
mirai_config_extractor.py – Extract and decrypt configuration data from
compiled Mirai botnet binaries.

Mirai stores its 52-entry configuration table (CnC domain, ports, HTTP
strings, attack payloads, etc.) XOR-obfuscated in the binary.  The
obfuscation is driven by a 32-bit integer ``table_key`` (global variable in
``bot/table.c``).  Each config byte is XORed with all four constituent bytes
of the key in sequence:

    encrypted_byte ^= k1  ( table_key        & 0xFF )
    encrypted_byte ^= k2  ((table_key >>  8) & 0xFF )
    encrypted_byte ^= k3  ((table_key >> 16) & 0xFF )
    encrypted_byte ^= k4  ((table_key >> 24) & 0xFF )

This is algebraically identical to a single-byte XOR with
``combined = k1 ^ k2 ^ k3 ^ k4``.  The default key is ``0xdeadbeef``
which gives ``combined = 0x22``.

Key-discovery strategy (tried in order)
----------------------------------------
1. **Capstone disassembly** – locate the ``toggle_obf`` XOR-loop and
   reconstruct ``table_key`` from the surrounding AND-0xFF / shift pattern
   for x86, MIPS, ARM, and PowerPC targets.
2. **Data-section scan** – scan every allocated ELF section for the raw
   4-byte key value (handles little- and big-endian layouts).
3. **Known-plaintext brute-force** – try all 256 possible combined XOR
   bytes and pick the one that yields the most printable ASCII candidate
   strings across the binary; also cross-checks against expected Mirai
   plaintext prefixes.

Usage
-----
    python3 mirai_config_extractor.py <binary>
    python3 mirai_config_extractor.py <binary> --key 0xdeadbeef
    python3 mirai_config_extractor.py <binary> --arch mips --endian big
    python3 mirai_config_extractor.py <binary> --raw        # skip ELF, treat as blob
    python3 mirai_config_extractor.py <binary> --min-len 4  # tune string scanner

Requirements
------------
    pip install capstone   # optional but recommended for disassembly-based search
"""

import argparse
import os
import re
import struct
import sys
from typing import Dict, Iterator, List, Optional, Tuple

try:
    import capstone
    import capstone.x86
    import capstone.mips
    import capstone.arm
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# ---------------------------------------------------------------------------
# Mirai configuration table metadata  (mirai/bot/table.h)
# ---------------------------------------------------------------------------

# Mapping: table_id → (constant_name, human_description, data_type)
# data_type: 'str' | 'port' | 'bool' | 'raw'
TABLE_ENTRIES: Dict[int, Tuple[str, str, str]] = {
    1:  ("TABLE_PROCESS_ARGV",               "Process argv string",                  "str"),
    2:  ("TABLE_EXEC_SUCCESS",               "Exec success marker",                  "str"),
    3:  ("TABLE_CNC_DOMAIN",                 "CnC / C2 domain",                      "str"),
    4:  ("TABLE_CNC_PORT",                   "CnC / C2 port",                        "port"),
    5:  ("TABLE_KILLER_SAFE",                "Killer safe URL",                      "str"),
    6:  ("TABLE_KILLER_PROC",                "Killer /proc path",                    "str"),
    7:  ("TABLE_KILLER_EXE",                 "Killer /exe path",                     "str"),
    8:  ("TABLE_KILLER_DELETED",             "Killer '(deleted)' suffix",            "str"),
    9:  ("TABLE_KILLER_FD",                  "Killer /fd path",                      "str"),
    10: ("TABLE_KILLER_ANIME",               "Killer .anime suffix",                 "str"),
    11: ("TABLE_KILLER_STATUS",              "Killer /status path",                  "str"),
    12: ("TABLE_MEM_QBOT",                   "QBot memory pattern 1",                "str"),
    13: ("TABLE_MEM_QBOT2",                  "QBot memory pattern 2",                "str"),
    14: ("TABLE_MEM_QBOT3",                  "QBot memory pattern 3",                "str"),
    15: ("TABLE_MEM_UPX",                    "UPX header pattern",                   "str"),
    16: ("TABLE_MEM_ZOLLARD",                "Zollard process name",                 "str"),
    17: ("TABLE_MEM_REMAITEN",               "Remaiten process name",                "str"),
    18: ("TABLE_SCAN_CB_DOMAIN",             "Scanner callback domain",              "str"),
    19: ("TABLE_SCAN_CB_PORT",               "Scanner callback port",                "port"),
    20: ("TABLE_SCAN_SHELL",                "'shell' telnet command",               "str"),
    21: ("TABLE_SCAN_ENABLE",               "'enable' telnet command",              "str"),
    22: ("TABLE_SCAN_SYSTEM",               "'system' telnet command",              "str"),
    23: ("TABLE_SCAN_SH",                   "'sh' telnet command",                  "str"),
    24: ("TABLE_SCAN_QUERY",                "Scanner login probe",                  "str"),
    25: ("TABLE_SCAN_RESP",                 "Scanner expected response",             "str"),
    26: ("TABLE_SCAN_NCORRECT",             "'ncorrect' bad-password marker",       "str"),
    27: ("TABLE_SCAN_PS",                   "Scanner ps command",                   "str"),
    28: ("TABLE_SCAN_KILL_9",               "Scanner kill -9 command",              "str"),
    29: ("TABLE_ATK_VSE",                   "Attack: VSE query string",             "str"),
    30: ("TABLE_ATK_RESOLVER",              "Attack: /etc/resolv.conf path",        "str"),
    31: ("TABLE_ATK_NSERV",                 "Attack: 'nameserver ' prefix",         "str"),
    32: ("TABLE_ATK_KEEP_ALIVE",            "HTTP header: Connection",              "str"),
    33: ("TABLE_ATK_ACCEPT",               "HTTP header: Accept",                  "str"),
    34: ("TABLE_ATK_ACCEPT_LNG",            "HTTP header: Accept-Language",         "str"),
    35: ("TABLE_ATK_CONTENT_TYPE",          "HTTP header: Content-Type",            "str"),
    36: ("TABLE_ATK_SET_COOKIE",            "HTTP setCookie() string",              "str"),
    37: ("TABLE_ATK_REFRESH_HDR",           "HTTP detection: refresh:",             "str"),
    38: ("TABLE_ATK_LOCATION_HDR",          "HTTP detection: location:",            "str"),
    39: ("TABLE_ATK_SET_COOKIE_HDR",        "HTTP detection: set-cookie:",          "str"),
    40: ("TABLE_ATK_CONTENT_LENGTH_HDR",    "HTTP detection: content-length:",      "str"),
    41: ("TABLE_ATK_TRANSFER_ENCODING_HDR", "HTTP detection: transfer-encoding:",   "str"),
    42: ("TABLE_ATK_CHUNKED",               "HTTP chunked transfer value",          "str"),
    43: ("TABLE_ATK_KEEP_ALIVE_HDR",        "HTTP detection: keep-alive",           "str"),
    44: ("TABLE_ATK_CONNECTION_HDR",        "HTTP detection: connection:",          "str"),
    45: ("TABLE_ATK_DOSARREST",             "DDoS guard fingerprint: DOSarrest",    "str"),
    46: ("TABLE_ATK_CLOUDFLARE_NGINX",      "DDoS guard fingerprint: Cloudflare",   "str"),
    47: ("TABLE_HTTP_ONE",                  "User-Agent: Chrome 51 / Win10",        "str"),
    48: ("TABLE_HTTP_TWO",                  "User-Agent: Chrome 52 / Win10",        "str"),
    49: ("TABLE_HTTP_THREE",                "User-Agent: Chrome 51 / Win6.1",       "str"),
    50: ("TABLE_HTTP_FOUR",                 "User-Agent: Chrome 52 / Win6.1",       "str"),
    51: ("TABLE_HTTP_FIVE",                "User-Agent: Safari / macOS",           "str"),
}

# Known default plaintext values from the public Mirai source (bot/table.c).
# Used to match extracted strings back to table IDs and to cross-check key guesses.
KNOWN_PLAINTEXTS: Dict[int, bytes] = {
    2:  b"listening tun0\x00",
    3:  b"cnc.changeme.com\x00",
    5:  b"https://youtu.be/dQw4w9WgXcQ\x00",
    6:  b"/proc/\x00",
    7:  b"/exe\x00",
    8:  b" (deleted)\x00",
    9:  b"/fd\x00",
    10: b".anime\x00",
    11: b"/status\x00",
    18: b"report.changeme.com\x00",
    20: b"shell\x00",
    21: b"enable\x00",
    22: b"system\x00",
    23: b"sh\x00",
    29: b"TSource Engine Query\x00",
    30: b"/etc/resolv.conf\x00",
    31: b"nameserver \x00",
    32: b"Connection: keep-alive\x00",
    33: b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\x00",
    34: b"Accept-Language: en-US,en;q=0.8\x00",
    35: b"Content-Type: application/x-www-form-urlencoded\x00",
    36: b"setCookie('\x00",
    37: b"refresh:\x00",
    38: b"location:\x00",
    39: b"set-cookie:\x00",
    40: b"content-length:\x00",
    41: b"transfer-encoding:\x00",
    42: b"chunked\x00",
    43: b"keep-alive\x00",
    44: b"connection:\x00",
    45: b"server: dosarrest\x00",
    46: b"server: cloudflare-nginx\x00",
}

# ---------------------------------------------------------------------------
# XOR helpers
# ---------------------------------------------------------------------------

def compute_xor_byte(key32: int) -> int:
    """Return the effective single-byte XOR value from a 32-bit Mirai table_key.

    Mirai applies all four key bytes one after another; the net result is XOR
    with k1 ^ k2 ^ k3 ^ k4.
    """
    k1 = key32 & 0xFF
    k2 = (key32 >> 8) & 0xFF
    k3 = (key32 >> 16) & 0xFF
    k4 = (key32 >> 24) & 0xFF
    return k1 ^ k2 ^ k3 ^ k4


def decrypt_bytes(data: bytes, xor_byte: int) -> bytes:
    """Decrypt (or encrypt – same operation) a block of Mirai XOR-encoded bytes."""
    return bytes(b ^ xor_byte for b in data)


def decrypt_cstring(data: bytes, xor_byte: int) -> str:
    """Decrypt and return a null-terminated config string (NUL stripped)."""
    dec = decrypt_bytes(data, xor_byte)
    try:
        end = dec.index(0)
        return dec[:end].decode("utf-8", errors="replace")
    except ValueError:
        return dec.decode("utf-8", errors="replace")


def decode_port(raw2: bytes, xor_byte: int) -> int:
    """Decrypt a 2-byte big-endian port number."""
    dec = decrypt_bytes(raw2[:2], xor_byte)
    return struct.unpack(">H", dec)[0]


def _ascii_score(data: bytes) -> float:
    """Return fraction of printable-ASCII bytes (0.0 – 1.0)."""
    if not data:
        return 0.0
    printable = sum(0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D) for b in data)
    return printable / len(data)


# ---------------------------------------------------------------------------
# ELF parser
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"


class ELFSection:
    """Lightweight representation of one ELF section header."""

    def __init__(self, name: str, sh_type: int, addr: int,
                 offset: int, size: int, flags: int) -> None:
        self.name = name
        self.sh_type = sh_type
        self.addr = addr
        self.offset = offset
        self.size = size
        self.flags = flags

    @property
    def is_alloc(self) -> bool:
        return bool(self.flags & 0x2)   # SHF_ALLOC

    @property
    def is_exec(self) -> bool:
        return bool(self.flags & 0x4)   # SHF_EXECINSTR


class ELFParser:
    """Minimal ELF parser for 32- and 64-bit, little- and big-endian binaries."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.valid = False
        self.bits = 32
        self.little_endian = True
        self.e_machine = 0
        self.sections: List[ELFSection] = []
        self._parse()

    # ------------------------------------------------------------------
    def _u16(self, off: int) -> int:
        fmt = "<H" if self.little_endian else ">H"
        return struct.unpack_from(fmt, self.data, off)[0]

    def _u32(self, off: int) -> int:
        fmt = "<I" if self.little_endian else ">I"
        return struct.unpack_from(fmt, self.data, off)[0]

    def _u64(self, off: int) -> int:
        fmt = "<Q" if self.little_endian else ">Q"
        return struct.unpack_from(fmt, self.data, off)[0]

    # ------------------------------------------------------------------
    def _parse(self) -> None:
        d = self.data
        if len(d) < 16 or d[:4] != ELF_MAGIC:
            return
        self.bits = 32 if d[4] == 1 else 64
        self.little_endian = (d[5] == 1)

        # e_machine is at offset 18 in both 32- and 64-bit ELF
        self.e_machine = self._u16(18)

        if self.bits == 32:
            if len(d) < 52:
                return
            e_shoff     = self._u32(32)
            e_shentsize = self._u16(46)
            e_shnum     = self._u16(48)
            e_shstrndx  = self._u16(50)
        else:
            if len(d) < 64:
                return
            e_shoff     = self._u64(40)
            e_shentsize = self._u16(58)
            e_shnum     = self._u16(60)
            e_shstrndx  = self._u16(62)

        self.valid = True
        self._parse_sections(e_shoff, e_shentsize, e_shnum, e_shstrndx)

    def _parse_sections(self, shoff: int, shentsize: int,
                        shnum: int, shstrndx: int) -> None:
        if shoff == 0 or shnum == 0:
            return

        # Load section-name string table (.shstrtab)
        strtab = b""
        if shstrndx < shnum:
            strtab = self._read_section_data(shoff, shentsize, shstrndx)

        for i in range(shnum):
            fields = self._parse_shdr(shoff, shentsize, i)
            if fields is None:
                continue
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = fields

            name = ""
            if strtab and sh_name < len(strtab):
                try:
                    end = strtab.index(b"\x00", sh_name)
                    name = strtab[sh_name:end].decode("ascii", errors="replace")
                except ValueError:
                    pass

            self.sections.append(ELFSection(
                name, sh_type, sh_addr, sh_offset, sh_size, sh_flags))

    def _parse_shdr(self, shoff: int, shentsize: int,
                    idx: int) -> Optional[Tuple[int, int, int, int, int, int]]:
        off = shoff + idx * shentsize
        d = self.data
        if self.bits == 32:
            if off + 40 > len(d):
                return None
            sh_name   = self._u32(off + 0)
            sh_type   = self._u32(off + 4)
            sh_flags  = self._u32(off + 8)
            sh_addr   = self._u32(off + 12)
            sh_offset = self._u32(off + 16)
            sh_size   = self._u32(off + 20)
        else:
            if off + 64 > len(d):
                return None
            sh_name   = self._u32(off + 0)
            sh_type   = self._u32(off + 4)
            sh_flags  = self._u64(off + 8)
            sh_addr   = self._u64(off + 16)
            sh_offset = self._u64(off + 24)
            sh_size   = self._u64(off + 32)
        return sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size

    def _read_section_data(self, shoff: int, shentsize: int, idx: int) -> bytes:
        fields = self._parse_shdr(shoff, shentsize, idx)
        if fields is None:
            return b""
        _, _, _, _, sh_offset, sh_size = fields
        return self.data[sh_offset: sh_offset + sh_size]

    # ------------------------------------------------------------------
    def section_data(self, sec: ELFSection) -> bytes:
        return self.data[sec.offset: sec.offset + sec.size]

    def exec_sections(self) -> List[ELFSection]:
        """Return executable sections (typically .text)."""
        return [s for s in self.sections
                if s.is_exec and s.sh_type == 1 and s.size > 0]

    def alloc_data_sections(self) -> List[ELFSection]:
        """Return allocated non-exec sections with file data (.data, .rodata …).

        SHT_NOBITS sections (.bss, sh_type=8) occupy no space in the file and
        are therefore excluded – they cannot contain encrypted config strings.
        """
        return [s for s in self.sections
                if s.is_alloc and not s.is_exec and s.size > 0
                and s.sh_type != 8]

    def read_at_vaddr(self, vaddr: int, size: int) -> Optional[bytes]:
        """Read ``size`` bytes at a virtual address via section offsets."""
        for sec in self.sections:
            if sec.addr and sec.addr <= vaddr < sec.addr + sec.size:
                raw_off = sec.offset + (vaddr - sec.addr)
                return self.data[raw_off: raw_off + size]
        return None

    @property
    def arch_name(self) -> str:
        return _ARCH_NAMES.get(self.e_machine, f"unk(e_machine=0x{self.e_machine:02X})")


# ---------------------------------------------------------------------------
# Architecture / capstone helpers
# ---------------------------------------------------------------------------

_ARCH_NAMES: Dict[int, str] = {
    0x02: "x86",    0x03: "x86",
    0x3E: "x86_64",
    0x08: "mips",
    0x28: "arm",
    0xB7: "aarch64",
    0x14: "ppc",    0x15: "ppc",
}

# e_machine → (cs_arch, cs_mode_base, display_name)
_CAPSTONE_MAP: Dict[int, Tuple] = {}
if HAS_CAPSTONE:
    _CAPSTONE_MAP = {
        0x02: (capstone.CS_ARCH_X86,   capstone.CS_MODE_32,               "x86"),
        0x03: (capstone.CS_ARCH_X86,   capstone.CS_MODE_32,               "x86"),
        0x3E: (capstone.CS_ARCH_X86,   capstone.CS_MODE_64,               "x86_64"),
        0x08: (capstone.CS_ARCH_MIPS,  capstone.CS_MODE_MIPS32,           "mips"),
        0x28: (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM,              "arm"),
        0xB7: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM,              "aarch64"),
        0x14: (capstone.CS_ARCH_PPC,   capstone.CS_MODE_32,               "ppc"),
        0x15: (capstone.CS_ARCH_PPC,   capstone.CS_MODE_32,               "ppc"),
    }


def _make_disassembler(e_machine: int, little_endian: bool):
    """Return a configured :class:`capstone.Cs` instance, or ``None``."""
    if not HAS_CAPSTONE:
        return None
    entry = _CAPSTONE_MAP.get(e_machine)
    if entry is None:
        return None
    cs_arch, cs_mode_base, _ = entry

    cs_mode = cs_mode_base
    if not little_endian:
        if cs_arch == capstone.CS_ARCH_MIPS:
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN
        elif cs_arch == capstone.CS_ARCH_PPC:
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    return md


# ---------------------------------------------------------------------------
# Key finding – Strategy 1: Capstone disassembly
# ---------------------------------------------------------------------------

def _find_key_x86(md, binary: bytes, parser: ELFParser,
                  verbose: bool) -> Optional[int]:
    """
    Find the XOR key in x86/x86_64 binaries.

    **Pattern A** – the compiler emits the XOR-loop with the key bytes as four
    consecutive byte-immediate XOR instructions (no optimisation):

        xor byte [reg+off], k1_imm
        xor byte [reg+off], k2_imm
        xor byte [reg+off], k3_imm
        xor byte [reg+off], k4_imm

    **Pattern B** – load ``table_key`` from a global address, then AND with
    ``0xFF`` to extract each sub-byte:

        mov  eax, [table_key_addr]
        movzx ecx, al              ; or  and eax, 0xff
        …
    """
    for sec in parser.exec_sections():
        code = binary[sec.offset: sec.offset + sec.size]
        base = sec.addr if sec.addr else 0
        try:
            insns = list(md.disasm(code, base))
        except Exception:
            continue

        # Pattern A – four consecutive xor-with-imm in a short window
        for i in range(len(insns)):
            if insns[i].mnemonic != "xor":
                continue
            imm_seq: List[int] = []
            j = i
            while j < len(insns) and j - i < 12:
                ins = insns[j]
                if ins.mnemonic == "xor" and ins.operands:
                    last_op = ins.operands[-1]
                    if last_op.type == capstone.x86.X86_OP_IMM:
                        imm_seq.append(last_op.imm & 0xFF)
                        if len(imm_seq) == 4:
                            break
                elif ins.mnemonic not in ("nop", "lea", "add", "sub",
                                          "inc", "dec", "cmp",
                                          "jne", "jl", "jg", "jle", "jge",
                                          "jb",  "ja", "jbe", "jae"):
                    break   # unrelated instruction interrupts the pattern
                j += 1

            if len(imm_seq) == 4:
                k1, k2, k3, k4 = imm_seq
                key32 = k1 | (k2 << 8) | (k3 << 16) | (k4 << 24)
                if verbose:
                    print(f"    [x86/patA] XOR-imm sequence "
                          f"0x{k1:02x},0x{k2:02x},0x{k3:02x},0x{k4:02x} "
                          f"→ key32={key32:#010x}")
                return key32

        # Pattern B – AND/movzx with 0xFF following a load from memory
        for i, insn in enumerate(insns):
            if insn.mnemonic not in ("and", "movzx"):
                continue
            has_ff = any(
                op.type == capstone.x86.X86_OP_IMM and (op.imm & 0xFFFF) == 0xFF
                for op in insn.operands
            )
            if not has_ff:
                continue
            for k in range(max(0, i - 8), i):
                prev = insns[k]
                if prev.mnemonic in ("mov", "movzx") and len(prev.operands) == 2:
                    src = prev.operands[1]
                    if src.type == capstone.x86.X86_OP_MEM and src.mem.disp:
                        key_addr = src.mem.disp & 0xFFFFFFFFFFFFFFFF
                        raw4 = parser.read_at_vaddr(key_addr, 4)
                        if raw4 and len(raw4) == 4:
                            fmt = "<I" if parser.little_endian else ">I"
                            key32 = struct.unpack(fmt, raw4)[0]
                            if verbose:
                                print(f"    [x86/patB] table_key loaded from "
                                      f"{key_addr:#x} → {key32:#010x}")
                            return key32
    return None


def _find_key_mips(md, binary: bytes, parser: ELFParser,
                   verbose: bool) -> Optional[int]:
    """
    Find the XOR key in MIPS binaries.

    The ``toggle_obf`` function contains:

        lw   $tX, <offset>($at)   ; load table_key
        andi $tY, $tX, 0xFF        ; k1  ← look for ≥2 of these in a window
        srl  $tZ, $tX, 8
        andi $tZ, $tZ, 0xFF        ; k2
        …

    We find clusters of ``andi reg, reg, 0xff`` and trace back to the
    preceding ``lw`` + ``lui`` pair to compute the ``table_key`` address.
    """
    for sec in parser.exec_sections():
        code = binary[sec.offset: sec.offset + sec.size]
        base = sec.addr if sec.addr else 0
        try:
            insns = list(md.disasm(code, base))
        except Exception:
            continue

        for i, insn in enumerate(insns):
            if insn.mnemonic != "andi":
                continue
            ops = insn.operands
            if len(ops) < 3 or ops[2].imm != 0xFF:
                continue

            # Count nearby andi … 0xFF instructions
            cluster = sum(
                1 for j in range(max(0, i - 2), min(len(insns), i + 20))
                if insns[j].mnemonic == "andi"
                and len(insns[j].operands) >= 3
                and insns[j].operands[2].imm == 0xFF
            )
            if cluster < 2:
                continue

            src_reg = ops[1].reg  # source register of this andi

            # Trace back to the lw that populated src_reg
            for k in range(i - 1, max(-1, i - 40), -1):
                lw = insns[k]
                if lw.mnemonic not in ("lw", "lhu", "lbu"):
                    continue
                if not lw.operands or lw.operands[0].reg != src_reg:
                    continue
                mem_op = lw.operands[1]
                if mem_op.type != capstone.mips.MIPS_OP_MEM:
                    continue
                lw_offset = mem_op.mem.disp
                base_reg  = mem_op.mem.base

                # Find the lui that set up base_reg
                for m in range(k - 1, max(-1, k - 25), -1):
                    lui = insns[m]
                    if lui.mnemonic != "lui":
                        continue
                    if not lui.operands or lui.operands[0].reg != base_reg:
                        continue
                    hi = lui.operands[1].imm & 0xFFFF
                    # Sign-extend the 16-bit LW offset
                    signed_off = lw_offset if lw_offset < 0x8000 else lw_offset - 0x10000
                    key_addr = ((hi << 16) + signed_off) & 0xFFFFFFFF
                    raw4 = parser.read_at_vaddr(key_addr, 4)
                    if raw4 and len(raw4) == 4:
                        fmt = "<I" if parser.little_endian else ">I"
                        key32 = struct.unpack(fmt, raw4)[0]
                        if verbose:
                            print(f"    [mips] table_key at vaddr "
                                  f"{key_addr:#x} → {key32:#010x}")
                        return key32
                break   # matched lw; stop looking further back
    return None


def _find_key_arm(md, binary: bytes, parser: ELFParser,
                  verbose: bool) -> Optional[int]:
    """
    Find the XOR key in 32-bit ARM binaries.

    The ``toggle_obf`` function contains:

        ldr  rX, [pc, #pool_offset]  ; load pointer to table_key
        ldr  rX, [rX]                ; dereference
        and  rY, rX, #0xFF           ; k1  ← look for ≥2 of these
        lsr  rZ, rX, #8
        and  rZ, rZ, #0xFF           ; k2
        …
    """
    for sec in parser.exec_sections():
        code = binary[sec.offset: sec.offset + sec.size]
        base_addr = sec.addr if sec.addr else 0
        try:
            insns = list(md.disasm(code, base_addr))
        except Exception:
            continue

        for i, insn in enumerate(insns):
            if insn.mnemonic not in ("and", "ands"):
                continue
            has_ff = any(
                op.type == capstone.arm.ARM_OP_IMM and op.imm == 0xFF
                for op in insn.operands
            )
            if not has_ff:
                continue

            cluster = sum(
                1 for j in range(max(0, i - 2), min(len(insns), i + 20))
                if insns[j].mnemonic in ("and", "ands")
                and any(op.type == capstone.arm.ARM_OP_IMM and op.imm == 0xFF
                        for op in insns[j].operands)
            )
            if cluster < 2:
                continue

            # Source register of the `and dst, src, #0xFF`
            src_reg = insn.operands[1].reg if len(insn.operands) >= 2 else None
            if src_reg is None:
                continue

            # Trace back to find `ldr src_reg, [src_reg]` (dereference)
            for k in range(i - 1, max(-1, i - 25), -1):
                ldr2 = insns[k]
                if ldr2.mnemonic not in ("ldr", "ldrb", "ldr.w"):
                    continue
                if not ldr2.operands or ldr2.operands[0].reg != src_reg:
                    continue
                mem2 = ldr2.operands[1]
                if mem2.type != capstone.arm.ARM_OP_MEM:
                    continue
                ptr_reg = mem2.mem.base

                # Find `ldr ptr_reg, [pc, #off]` – loads the pointer itself
                for m in range(k - 1, max(-1, k - 20), -1):
                    ldr1 = insns[m]
                    if ldr1.mnemonic not in ("ldr", "ldr.w"):
                        continue
                    if not ldr1.operands or ldr1.operands[0].reg != ptr_reg:
                        continue
                    mem1 = ldr1.operands[1]
                    if mem1.type != capstone.arm.ARM_OP_MEM:
                        continue
                    # Literal-pool address: (PC aligned to 4) + offset
                    pool_addr = (ldr1.address + 8 + mem1.mem.disp) & ~0x3
                    pool_data = parser.read_at_vaddr(pool_addr, 4)
                    if not pool_data:
                        continue
                    key_ptr = struct.unpack("<I", pool_data)[0]
                    raw4 = parser.read_at_vaddr(key_ptr, 4)
                    if raw4 and len(raw4) == 4:
                        key32 = struct.unpack("<I", raw4)[0]
                        if verbose:
                            print(f"    [arm] table_key ptr pool={pool_addr:#x} "
                                  f"key_ptr={key_ptr:#x} → {key32:#010x}")
                        return key32
                break
    return None


def _find_key_generic(md, binary: bytes, parser: ELFParser,
                      verbose: bool) -> Optional[int]:
    """
    Generic fallback: scan all executable sections for four consecutive
    XOR instructions whose immediates could be the four key bytes.
    Useful for PowerPC and other architectures.
    """
    xor_mnemonics = {"xor", "eor", "xori", "xoris"}
    for sec in parser.exec_sections():
        code = binary[sec.offset: sec.offset + sec.size]
        base = sec.addr if sec.addr else 0
        try:
            insns = list(md.disasm(code, base))
        except Exception:
            continue

        for i in range(len(insns) - 3):
            window = insns[i: i + 8]
            xor_imms = []
            for ins in window:
                if ins.mnemonic not in xor_mnemonics:
                    break
                if ins.operands:
                    last = ins.operands[-1]
                    # Accept any immediate operand type
                    imm_val = getattr(last, "imm", None)
                    if imm_val is not None:
                        xor_imms.append(imm_val & 0xFF)
            if len(xor_imms) >= 4:
                k1, k2, k3, k4 = xor_imms[:4]
                key32 = k1 | (k2 << 8) | (k3 << 16) | (k4 << 24)
                if verbose:
                    print(f"    [generic] XOR-imm sequence "
                          f"0x{k1:02x},0x{k2:02x},0x{k3:02x},0x{k4:02x} "
                          f"→ key32={key32:#010x}")
                return key32
    return None


def find_key_via_capstone(parser: ELFParser, binary: bytes,
                          verbose: bool = False) -> Optional[int]:
    """
    Dispatch to the architecture-specific disassembly-based key finder.

    Returns the 32-bit ``table_key`` integer, or ``None`` if not found.
    """
    if not HAS_CAPSTONE:
        return None
    md = _make_disassembler(parser.e_machine, parser.little_endian)
    if md is None:
        if verbose:
            print(f"  [capstone] Unsupported architecture "
                  f"e_machine={parser.e_machine:#x} – skipping.")
        return None

    arch = parser.arch_name
    if verbose:
        print(f"  [capstone] Disassembling {arch} binary …")

    if arch in ("x86", "x86_64"):
        key = _find_key_x86(md, binary, parser, verbose)
    elif arch == "mips":
        key = _find_key_mips(md, binary, parser, verbose)
    elif arch in ("arm", "aarch64"):
        key = _find_key_arm(md, binary, parser, verbose)
    else:
        key = _find_key_generic(md, binary, parser, verbose)

    if key is not None and verbose:
        print(f"  [capstone] Key found: {key:#010x} "
              f"(combined XOR byte: {compute_xor_byte(key):#04x})")
    return key


# ---------------------------------------------------------------------------
# Key finding – Strategy 2: Data-section byte scan
# ---------------------------------------------------------------------------

# Well-known Mirai keys: the default 0xdeadbeef and a few variants seen in
# the wild (stored as little-endian uint32 in .data).
_WELL_KNOWN_KEYS = [
    0xdeadbeef,
    0xfeedbeef,
    0xbeefdead,
    0xcafebabe,
    0xdeadc0de,
    0x12345678,
]


def find_key_in_data(parser: ELFParser, binary: bytes,
                     verbose: bool = False) -> Optional[int]:
    """
    Scan every allocated ELF section for the literal 4-byte ``table_key``
    value.  Both little-endian and big-endian representations are checked.

    Prefers well-known Mirai keys when found; otherwise scores each candidate
    4-byte value against known plaintext prefixes to avoid returning the wrong
    key (e.g. a repeated pointer or string constant that happens to occupy a
    data section).
    """
    # First pass: look for well-known keys verbatim anywhere in the binary
    for k in _WELL_KNOWN_KEYS:
        le_bytes = struct.pack("<I", k)
        be_bytes = struct.pack(">I", k)
        if le_bytes in binary or be_bytes in binary:
            if verbose:
                print(f"  [data-scan] Well-known key {k:#010x} found in binary")
            return k

    # Second pass: score each 4-byte aligned value in allocated data sections
    # by checking how many known-plaintext encrypted prefixes it produces that
    # are actually present in the binary.  A correct table_key will cause many
    # such hits; an unrelated constant will cause few or none.
    best_key: Optional[int] = None
    best_score = 0
    for sec in parser.alloc_data_sections():
        data = parser.section_data(sec)
        for off in range(0, len(data) - 3, 4):
            chunk = data[off: off + 4]
            for fmt in ("<I", ">I"):
                val = struct.unpack(fmt, chunk)[0]
                if val in (0, 0xFFFFFFFF):
                    continue
                xb = compute_xor_byte(val)
                if xb == 0:
                    continue  # degenerate key (no obfuscation)
                # Score: count how many known encrypted prefixes (for this
                # combined XOR byte) appear verbatim in the binary.
                score = sum(
                    1 for enc_prefix, xb2 in _KNOWN_ENC_PREFIXES
                    if xb2 == xb and enc_prefix in binary
                )
                if score > best_score:
                    best_score = score
                    best_key = val

    if best_key is not None and best_score > 0:
        if verbose:
            print(f"  [data-scan] Best candidate key: {best_key:#010x} "
                  f"(plaintext prefix matches: {best_score})")
        return best_key

    return None


# ---------------------------------------------------------------------------
# Key finding – Strategy 3: Known-plaintext brute-force
# ---------------------------------------------------------------------------

def _build_known_enc_prefixes() -> List[Tuple[bytes, int]]:
    """
    Pre-compute the encrypted prefixes of every known plaintext for all 256
    possible combined XOR bytes.  Returns list of (enc_prefix_4, xor_byte).
    """
    result = []
    for _eid, plaintext in KNOWN_PLAINTEXTS.items():
        if len(plaintext) < 4:
            continue
        prefix4 = plaintext[:4]
        for xb in range(256):
            enc = bytes(b ^ xb for b in prefix4)
            result.append((enc, xb))
    return result


_KNOWN_ENC_PREFIXES = _build_known_enc_prefixes()


def find_key_bruteforce(binary: bytes, verbose: bool = False) -> Optional[int]:
    """
    Try all 256 possible combined XOR bytes and score each by:

    1. **Prefix match** – bonus when the decrypted binary contains the first
       four bytes of a known Mirai plaintext.
    2. **String count** – number of candidate null-terminated ASCII strings
       of length ≥ 4 after XOR-decryption.  Weighted by string length so
       longer strings contribute more to the score.

    Returns a ``key32`` value whose ``compute_xor_byte()`` equals the best
    combined XOR byte.  (Only the combined byte matters for decryption.)
    """
    # Scoring constants
    PREFIX_MATCH_BONUS    = 10   # per known-plaintext prefix found in binary
    PREFIX_WIN_MARGIN     = 5    # top candidate must beat runner-up by this much
    STRING_BASE_SCORE     = 0.5  # awarded for each plausible null-terminated string
    STRING_LENGTH_WEIGHT  = 0.02 # additional score per byte of string length
    # Longest known Mirai config entry (TABLE_ATK_ACCEPT ~86 bytes); add margin
    MAX_STRING_SCAN_LEN   = 200

    # Fast prefix scan: check which combined bytes produce known-plaintext hits
    prefix_scores: Dict[int, int] = {}
    for enc_prefix, xb in _KNOWN_ENC_PREFIXES:
        if enc_prefix in binary:
            prefix_scores[xb] = prefix_scores.get(xb, 0) + PREFIX_MATCH_BONUS

    # If a single candidate clearly dominates on prefix matches, use it
    if prefix_scores:
        top_xb = max(prefix_scores, key=lambda x: prefix_scores[x])
        runner_up = sorted(prefix_scores.values(), reverse=True)
        # Accept if clearly ahead (or only one candidate)
        if len(runner_up) == 1 or runner_up[0] >= runner_up[1] + PREFIX_WIN_MARGIN:
            if verbose:
                print(f"  [bruteforce] Prefix-match winner: "
                      f"combined XOR byte = {top_xb:#04x} "
                      f"(score={prefix_scores[top_xb]})")
            # Encode combined_byte as a key32 with only the low byte set so
            # that compute_xor_byte(key32) returns the same combined_byte.
            return top_xb   # see note below *

    # Full-scan scoring for all 256 bytes
    best_score = -1.0
    best_xb = 0x22  # default fallback

    # Pre-compile regex for printable null-terminated runs.
    # Upper bound covers the longest known Mirai config strings with extra margin.
    scan_pattern = re.compile(
        rb"[ -~\t\n\r]{4," + str(MAX_STRING_SCAN_LEN).encode() + rb"}\x00"
    )

    for xb in range(256):
        score = float(prefix_scores.get(xb, 0))

        # Decrypt and count plausible strings
        dec = bytes(b ^ xb for b in binary)
        for m in scan_pattern.finditer(dec):
            score += STRING_BASE_SCORE + len(m.group()) * STRING_LENGTH_WEIGHT

        if score > best_score:
            best_score = score
            best_xb = xb

    if verbose:
        print(f"  [bruteforce] Best combined XOR byte = {best_xb:#04x} "
              f"(score={best_score:.1f})")

    # * We return the combined byte directly as 'key32' with only the low
    #   byte set (k2=k3=k4=0), so compute_xor_byte(key32) == best_xb.
    return best_xb


def _xor_byte_to_key32(xb: int) -> int:
    """
    Convert a combined XOR byte back into a minimal key32 representation.

    Sets only k1 (low byte) of the key to ``xb``; the other three bytes are
    zero so that ``compute_xor_byte(key32) == xb``.
    """
    return xb  # k1=xb, k2=k3=k4=0  → k1^k2^k3^k4 = xb


# ---------------------------------------------------------------------------
# Orchestrate key finding
# ---------------------------------------------------------------------------

def find_key(binary: bytes, parser: Optional[ELFParser],
             verbose: bool = False) -> Tuple[Optional[int], str]:
    """
    Try all key-finding strategies in priority order.

    Returns ``(key32, source_description)``.  ``key32`` is ``None`` only
    when all strategies fail.

    .. note::
       For the brute-force strategy the returned ``key32`` encodes only the
       combined XOR byte (k1 = xor_byte, k2 = k3 = k4 = 0).  This is
       sufficient for decryption because only ``compute_xor_byte(key32)``
       is used downstream.  The actual full 32-bit key (e.g. ``0xdeadbeef``)
       can only be recovered via capstone or data-section scan.
    """
    if parser and parser.valid:
        # Strategy 1: capstone disassembly
        key = find_key_via_capstone(parser, binary, verbose)
        if key is not None:
            return key, "capstone disassembly"

        # Strategy 2: data-section literal scan
        key = find_key_in_data(parser, binary, verbose)
        if key is not None:
            return key, "data-section scan"

    # Strategy 3: known-plaintext / brute-force
    key = find_key_bruteforce(binary, verbose)
    if key is not None:
        return key, "known-plaintext / brute-force"

    return None, "none"


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

def extract_encrypted_strings(
    binary: bytes,
    xor_byte: int,
    min_len: int = 3,
    regions: Optional[List[Tuple[int, int]]] = None,
) -> List[Tuple[int, bytes, str]]:
    """
    Scan *binary* for XOR-encoded null-terminated ASCII strings.

    The encrypted null byte is always ``xor_byte`` itself (since
    ``0x00 ^ xor_byte == xor_byte``).  The algorithm makes a forward pass
    over each region, collecting maximal runs of bytes that:

      * are NOT equal to ``xor_byte`` (i.e. not an encrypted null), AND
      * are NOT a literal ``0x00`` byte (raw nulls in the file are padding or
        code, not encrypted config bytes, and would otherwise decode to
        ``xor_byte`` which is often printable – e.g. 0x22 = '"'), AND
      * decrypt (XOR with ``xor_byte``) to a printable ASCII character.

    Each such run that is immediately followed by ``xor_byte`` and is at
    least ``min_len`` bytes long is treated as one encrypted config string.

    Parameters
    ----------
    regions:
        Optional list of ``(file_offset, byte_length)`` pairs that restrict
        the scan to specific byte ranges (e.g. ELF ``.rodata`` / ``.data``
        sections).  When ``None`` the entire binary is scanned.  Restricting
        to allocated data sections eliminates false positives caused by the
        ELF header, zero-padded code sections, and other non-data regions.

    Returns a deduplicated list of ``(file_offset, raw_enc_bytes, decrypted_str)``.
    """
    enc_null = xor_byte
    seen: Dict[str, bool] = {}
    results: List[Tuple[int, bytes, str]] = []

    def _scan(base: int, data: bytes) -> None:
        run_start: Optional[int] = None
        for rel_i, b in enumerate(data):
            abs_i = base + rel_i

            if b == enc_null:
                # Encrypted null terminator – ends the current run (if any).
                if run_start is not None:
                    length = abs_i - run_start
                    if length >= min_len:
                        raw = binary[run_start:abs_i]
                        dec = decrypt_bytes(raw, xor_byte)
                        # Require high ASCII printability (tolerate a few
                        # non-printable bytes in long strings, e.g. embedded
                        # control chars from attack payloads).
                        if _ascii_score(dec) >= 0.85:
                            s = dec.decode("utf-8", errors="replace")
                            if s not in seen:
                                seen[s] = True
                                results.append((run_start, raw, s))
                run_start = None
            elif b == 0x00:
                # Literal null byte in the file: not an encrypted config byte.
                # Without this guard, 0x00 XOR xor_byte often equals a
                # printable character (e.g. 0x00 ^ 0x22 = 0x22 = '"'),
                # causing runs to bleed across zero-padded regions and merge
                # ELF-header / code-section garbage with real config strings.
                run_start = None
            else:
                dec_b = b ^ xor_byte
                if 0x20 <= dec_b <= 0x7E or dec_b in (0x09, 0x0A, 0x0D):
                    # Printable byte – start or continue a run.
                    if run_start is None:
                        run_start = abs_i
                else:
                    # Non-printable byte – break any active run.
                    run_start = None

    if regions:
        for off, size in regions:
            end = min(off + size, len(binary))
            if off < end:
                _scan(off, binary[off:end])
    else:
        _scan(0, binary)

    return results


# ---------------------------------------------------------------------------
# Map extracted strings to TABLE_* entry IDs
# ---------------------------------------------------------------------------

def _build_plaintext_lookup() -> Dict[str, int]:
    """Map known plaintext (without NUL) → TABLE_* id."""
    lut: Dict[str, int] = {}
    for eid, raw in KNOWN_PLAINTEXTS.items():
        text = raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        lut[text] = eid
    return lut


_PLAINTEXT_LUT = _build_plaintext_lookup()


def match_to_entry_id(s: str) -> Optional[int]:
    """Return a TABLE_* id for a decrypted string, or ``None``."""
    return _PLAINTEXT_LUT.get(s)


# ---------------------------------------------------------------------------
# Port / value decoding
# ---------------------------------------------------------------------------

def format_value(s: str, raw: bytes, xor_byte: int,
                 entry_id: Optional[int]) -> str:
    """Return a human-readable representation of a decrypted config value."""
    if entry_id is None:
        return s
    _, _, dtype = TABLE_ENTRIES.get(entry_id, ("", "", "str"))
    if dtype == "port" and len(raw) >= 2:
        try:
            port = decode_port(raw, xor_byte)
            return f"{port}  (0x{port:04X})"
        except Exception:
            pass
    return s


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_SEP_DOUBLE = "═" * 78
_SEP_SINGLE = "─" * 78


def display_results(
    results: List[Tuple[int, bytes, str]],
    xor_byte: int,
    key32: Optional[int],
    key_source: str,
    binary_path: str,
    parser: Optional[ELFParser],
) -> None:
    """Print a formatted report of extracted and decrypted config entries."""
    print()
    print(_SEP_DOUBLE)
    print("  Mirai Configuration Extractor – Results")
    print(_SEP_DOUBLE)
    print(f"  Binary : {binary_path}")
    if parser and parser.valid:
        endian = "little-endian" if parser.little_endian else "big-endian"
        print(f"  Format : ELF {parser.bits}-bit {endian} ({parser.arch_name})")
    if key32 is not None:
        full_key = f"0x{key32:08X}" if key32 > 0xFF else "derived from combined byte"
        print(f"  Key    : {full_key}")
    print(f"  XOR    : 0x{xor_byte:02X}  (effective single-byte XOR)")
    print(f"  Source : {key_source}")
    print(f"  Found  : {len(results)} unique encrypted string(s)")
    print(_SEP_SINGLE)

    if not results:
        print("  No decrypted strings found.")
        print("  Hints: try --key <hex>, --min-len 4, or --raw for non-ELF blobs.")
        print(_SEP_DOUBLE)
        return

    matched: Dict[int, Tuple[str, bytes]] = {}
    unmatched: List[Tuple[int, str, bytes]] = []

    for off, raw, s in results:
        eid = match_to_entry_id(s)
        value = format_value(s, raw, xor_byte, eid)
        if eid is not None:
            matched[eid] = (value, raw)
        else:
            unmatched.append((off, value, raw))

    if matched:
        print("\n  ── Recognised Mirai table entries ───────────────────────\n")
        for eid in sorted(matched.keys()):
            cname, desc, _ = TABLE_ENTRIES.get(eid, ("?", "unknown", "str"))
            value, _ = matched[eid]
            print(f"  [{eid:>2}] {cname:<40} {repr(value)}")
            print(f"       {desc}")
        print()

    if unmatched:
        print("  ── Additional decrypted strings (not in default table) ───\n")
        for off, value, _ in sorted(unmatched, key=lambda x: x[0]):
            print(f"  [0x{off:08x}]  {repr(value)}")
        print()

    print(_SEP_DOUBLE)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_ARCH_MACHINE_MAP: Dict[str, int] = {
    "x86":     0x02, "i386":    0x02, "i586":    0x02,
    "x86_64":  0x3E, "amd64":   0x3E,
    "mips":    0x08, "mipsel":  0x08,
    "arm":     0x28, "armv4l":  0x28, "armv5l":  0x28, "armv6l":  0x28,
    "aarch64": 0xB7, "arm64":   0xB7,
    "ppc":     0x14, "powerpc": 0x14,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mirai_config_extractor.py",
        description=(
            "Extract and decrypt the configuration table from a compiled "
            "Mirai botnet binary.  Automatically searches for the XOR key "
            "using capstone disassembly, data-section scanning, and "
            "known-plaintext brute-force."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s mirai.mips
  %(prog)s mirai.x86   --key 0xdeadbeef
  %(prog)s mirai.arm   --arch arm --endian little
  %(prog)s firmware.bin --raw --min-len 6
        """,
    )
    p.add_argument("binary", help="Path to the compiled Mirai binary")
    p.add_argument(
        "--key", "-k",
        metavar="0xHEX",
        help="Explicit 32-bit XOR key (e.g. 0xdeadbeef).  Skips auto-detection.",
    )
    p.add_argument(
        "--arch", "-a",
        choices=sorted(_ARCH_MACHINE_MAP.keys()),
        help="Override detected CPU architecture (affects capstone disassembly).",
    )
    p.add_argument(
        "--endian", "-e",
        choices=["little", "big"],
        help="Override endianness (affects capstone disassembly).",
    )
    p.add_argument(
        "--raw",
        action="store_true",
        help="Treat the input as a raw binary blob; skip ELF parsing.",
    )
    p.add_argument(
        "--min-len", "-m",
        type=int,
        default=3,
        dest="min_len",
        metavar="N",
        help="Minimum decrypted string length to report (default: 3).",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print key-search diagnostic information.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not HAS_CAPSTONE and not args.key:
        print(
            "[!] capstone is not installed.  Disassembly-based key search "
            "disabled.\n"
            "    Install with: pip install capstone\n"
            "    Falling back to data-section scan and brute-force.\n",
            file=sys.stderr,
        )

    if not os.path.isfile(args.binary):
        print(f"Error: file not found: {args.binary}", file=sys.stderr)
        return 1

    with open(args.binary, "rb") as fh:
        binary = fh.read()

    if not binary:
        print("Error: binary is empty.", file=sys.stderr)
        return 1

    # Parse ELF (unless --raw)
    parser: Optional[ELFParser] = None
    if not args.raw:
        parser = ELFParser(binary)
        if not parser.valid:
            print(
                "[!] Not a valid ELF binary – switching to raw blob mode.",
                file=sys.stderr,
            )
            parser = None

    # Apply user overrides for architecture / endianness
    if parser:
        if args.arch:
            parser.e_machine = _ARCH_MACHINE_MAP.get(args.arch, parser.e_machine)
        if args.endian:
            parser.little_endian = args.endian == "little"

    # ---- Determine the XOR key ----------------------------------------
    if args.key:
        try:
            key32 = int(args.key, 16)
        except ValueError:
            print(
                f"Error: invalid key '{args.key}' "
                "(expected hex, e.g. 0xdeadbeef)",
                file=sys.stderr,
            )
            return 1
        xor_byte = compute_xor_byte(key32)
        key_source = "command-line argument"
        if args.verbose:
            print(f"[*] Using provided key {key32:#010x}  "
                  f"(combined XOR byte {xor_byte:#04x})")
    else:
        if args.verbose:
            print("[*] Searching for XOR key …")
        key32, key_source = find_key(binary, parser, verbose=args.verbose)
        if key32 is None:
            print(
                "[!] Could not determine the XOR key.\n"
                "    Provide one manually with --key 0xDEADBEEF",
                file=sys.stderr,
            )
            return 1
        xor_byte = compute_xor_byte(key32)
        if args.verbose:
            print(
                f"[*] Key found via {key_source}: "
                f"combined XOR byte = {xor_byte:#04x}"
            )

    # ---- Extract and display ------------------------------------------
    # For ELF binaries restrict scanning to allocated data sections
    # (.rodata, .data, etc.) so that the ELF header, code sections, and
    # zero-padded regions do not produce false-positive strings.
    scan_regions: Optional[List[Tuple[int, int]]] = None
    if parser and parser.valid:
        data_secs = parser.alloc_data_sections()
        if data_secs:
            scan_regions = [(sec.offset, sec.size) for sec in data_secs]
    results = extract_encrypted_strings(
        binary, xor_byte, min_len=args.min_len, regions=scan_regions)
    display_results(results, xor_byte, key32, key_source, args.binary, parser)
    return 0


if __name__ == "__main__":
    sys.exit(main())
