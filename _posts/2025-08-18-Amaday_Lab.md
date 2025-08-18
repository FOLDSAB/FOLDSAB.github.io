---
layout: post
title: "Amadey Lab Writeup"
date: 2025-08-17 09:49:00 +0000
tags: [Endpoint Forensics]
categories: [Cyber Defenders Writeup]
---

> ### Q1. In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?

To find the parent process, the `windows.pstree` or `windows.cmdline` plugin can be used. At first, using `windows.pstree`, the suspicious process was not obvious, so it seemed better to switch to `windows.cmdline` and come back to `pstree` if needed.
![pstree.png](/assets/img/Amadey_Lab/pstree.png)

Using `windows.cmdline`, no suspicious commands were found initially. However, when searching for processes in the "Temp" folder (a common place for malware to hide), a process named `lssass.exe` was identified. It is very similar to the legitimate `lsass.exe` system process, which handles authentication and user logins, but it has an extra 's', a common trick malware uses to hide itself.

![cmdline_temp.png](/assets/img/Amadey_Lab/cmdline_temp.png)

---

> ### Q2. Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?

The path of the process was already discovered while looking for "Temp" in Q1. The malware resides in the Temp folder.

---

> ### Q3. Persistent external communications suggest the malware's attempts to reach out to a C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?

The malware attempts to connect to a Command and Control server. Using `windows.netscan` to check network connections, it was found that `lssass.exe` was communicating with the external IP `47.75.84.12` on port 80.

![netscan.png](/assets/img/Amadey_lab/netscan.png)

---

> ### Q4. Following the malware link with the C2C, the malware is likely fetching additional tools or modules. How many distinct files is it trying to bring onto the compromised workstation?

To check which files the malware is fetching, we need to see its HTTP requests to the C2C server on port 80. Using `windows.memmap`, the process was dumped and then strings were extracted to view the requests.

![dump_process.png](/assets/img/Amadey_lab/dump_process.png)

From the dumped process (`pid.2748.dmp`), two GET requests were found for `cred64.dll` and `clip64.dll`. So, the malware is trying to fetch **two distinct files**.

![request.png](/assets/img/Amadey_lab/request.png)

---

> ### Q5. Identifying the storage points of these additional components is critical for containment and cleanup. What is the full path of the file downloaded and used by the malware in its malicious activity?

These files must have been executed by the malware or its child process. Using `windows.cmdline` to inspect the command lines, it was found that `rundll32.exe` is executing `clip64.dll`. This also revealed the **full path of the downloaded file**.

![rundll_32_commandline.png](/assets/img/Amadey_lab/rundll_32_commandline.png)

---

> ### Q6. Once retrieved, the malware aims to activate its additional components. Which child process is initiated by the malware to execute these files?

This was already identified in Q5: the child process used to execute the files is **`rundll32.exe`**.

---

> ### Q7. Understanding the full range of Amadey's persistence mechanisms can help in effective mitigation. Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?

To find other locations where the malware may persist, `windows.filescan` can be used to search the filesystem. By searching for `lssass.exe`, we can see additional paths where the malware copied itself for persistence.

![last_one.png](/assets/img/Amadey_lab/last_one.png)


