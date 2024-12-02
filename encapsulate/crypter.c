#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD_SIZE 1024  // Maximum size of the payload

unsigned char shellcode_payload[MAX_PAYLOAD_SIZE];
size_t payload_size = 0;

// Function prototypes
void load_shellcode_from_csv(const char *csv_filename);
void print_file_contents(const char *filename, int rotation_value);
void rot_n(unsigned char *byte, int n);

int main() {
    const char *csv_filename = "shellcode.csv";  // CSV file containing shellcode
    const char *output_filename = "encrypted.bin";  // Output file to write encrypted data
    int rotation_value = 33;  // Example: ROT33 encryption

    // Load the shellcode from the CSV file
    load_shellcode_from_csv(csv_filename);

    if (payload_size == 0) {
        fprintf(stderr, "Error: Shellcode payload is empty!\n");
        return 1;
    }

    // Open the output file in binary write mode
    FILE *file = fopen(output_filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Encrypt and write the shellcode payload to the file
    for (size_t i = 0; i < payload_size; i++) {
        unsigned char encrypted_byte = shellcode_payload[i];
        rot_n(&encrypted_byte, rotation_value);  // Encrypt each byte
        fwrite(&encrypted_byte, sizeof(unsigned char), 1, file);  // Write encrypted byte to file
    }

    // Close the file after writing
    fclose(file);

    // Print the contents of the file after decrypting byte-by-byte
    print_file_contents(output_filename, rotation_value);

    return 0;
}

void load_shellcode_from_csv(const char *csv_filename) {
    FILE *csv_file = fopen(csv_filename, "r");
    if (csv_file == NULL) {
        perror("Error opening CSV file");
        return;
    }

    char buffer[1024];
    size_t buf_index = 0; // Buffer index for reading character by character
    int c;

    payload_size = 0;

    // Custom getline logic with ',' as delimiter and skipping newlines
    while ((c = fgetc(csv_file)) != EOF) {
        if (c == ',' || c == '\n') {
            if (buf_index > 0) { // Process the collected token
                buffer[buf_index] = '\0'; // Null-terminate the string
                int value = strtol(buffer, NULL, 16); // Convert to integer
                if (value < 0 || value > 255) {
                    fprintf(stderr, "Invalid byte value: %s\n", buffer);
                    fclose(csv_file);
                    return;
                }
                shellcode_payload[payload_size++] = (unsigned char)value;
                if (payload_size >= MAX_PAYLOAD_SIZE) {
                    fprintf(stderr, "Payload size exceeds maximum allowed size!\n");
                    fclose(csv_file);
                    return;
                }
                buf_index = 0; // Reset buffer index for next token
            }
        } else {
            buffer[buf_index++] = (char)c; // Store character in the buffer
            if (buf_index >= sizeof(buffer) - 1) { // Prevent buffer overflow
                fprintf(stderr, "Token too long in CSV file!\n");
                fclose(csv_file);
                return;
            }
        }
    }

    // Handle the last token if present
    if (buf_index > 0) {
        buffer[buf_index] = '\0';
        int value = strtol(buffer, NULL, 16);
        if (value < 0 || value > 255) {
            fprintf(stderr, "Invalid byte value: %s\n", buffer);
            fclose(csv_file);
            return;
        }
        shellcode_payload[payload_size++] = (unsigned char)value;
        if (payload_size >= MAX_PAYLOAD_SIZE) {
            fprintf(stderr, "Payload size exceeds maximum allowed size!\n");
            fclose(csv_file);
            return;
        }
    }

    fclose(csv_file);
}


void print_file_contents(const char *filename, int rotation_value) {
    // Open the file in binary read mode
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    unsigned char byte;
    // Read and decrypt each byte in the file
    while (fread(&byte, sizeof(unsigned char), 1, file) == 1) {
        rot_n(&byte, -rotation_value);  // Decrypt each byte (reverse ROTN)
        printf("%02x ", byte);  // Print decrypted byte in hex
    }

    // Close the file
    fclose(file);
    printf("\n");
}

// ROTN function to encrypt or decrypt a byte
void rot_n(unsigned char *byte, int n) {
    // Apply ROT-N to the byte (ensure it's in the range 0-255)
    *byte = (*byte + n + 256) % 256;  // Add 256 to ensure non-negative results for decryption
}
