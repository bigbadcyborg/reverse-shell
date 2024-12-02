// socket_part.c
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

SOCKET create_socket(const char *ip_addr, int port) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    // Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create socket
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return INVALID_SOCKET;
    }

    // Set up server structure
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip_addr);

    // Connect to listener
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) != 0) {
        printf("Connection failed\n");
        closesocket(sock);
        WSACleanup();
        return INVALID_SOCKET;
    }

    return sock;
}