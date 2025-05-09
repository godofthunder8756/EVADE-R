import lief

# parse the PE
binary = lief.PE.parse("payload.exe")
if not binary:
    print("Failed to parse payload.exe")
    exit(1)

# grab the COFF machine field
machine = binary.header.machine

# compare to the enum on PE.Header
if machine == lief.PE.Header.MACHINE_TYPES.AMD64:
    print("This is a 64-bit PE file")
elif machine == lief.PE.Header.MACHINE_TYPES.I386:
    print("This is a 32-bit PE file")
else:
    print(f"Unknown architecture: {machine}")
