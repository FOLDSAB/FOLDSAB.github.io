---
layout: post
title: "Sagerunex Analysis"
date: 2026-04-20 13:47:00 +0000
tags: [Malware Analysis]
categories: [Malops Writeups]
---

Sagerunex Analysis - Malops
---

Fire up your VM and let the chase begin. 

First lets look on the executable, According to DIE it's a 64 bit DLL file, compiled using microsoft visual 2013. This is just enough to get started. 
![DIE_details](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/DIE_details.png)



### Q1. What is the exact compilation time of the malicious executable? (UTC)

---> To answer this question DIE is also capable, however we need to provide the time on UTC then why not use a opensource analyzer to see if this thing is already detected on the wild and have some information about it and what we are looking for as well. what may be handy on this case ? virustotal, lets get the hash and paste it there. 

![Creation_time](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/creation_time.png)

from the figure above we got our creation time i.e. `2021-03-15 09:44:36 UTC` and many detials regarding it. 

### Q2. What is the exact filename used by the malware for logging its operations?



doing static analysis, it uses [GetTempPathW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppathw) API to get the tem file location and then concat location with file name `TS_FB56.tmp`.

![filename](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/filename.png)

 Getting the temp path and concatting it with a filename, what could be more suspecious of malware then a temp file location on it. 


### Q3. What is the magic value used to validate the malware configuration before executing token impersonation? (HEX)

--> so, now we have to find something related to conditional check before malware executes token impersonation. so, one of Windows API useful for token impersonation is [DuplicateToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken) API, so, if we found this being used and a condition before it then it must be that magic value. 

while moving forward with some reverse engineering, we got to a if condition, which check for a hex value ```0xc91f3b```

![hexvalue](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/magic_value.png)


keeping that on mind if we move forward to function FUN_180003284() `(may be changed while getting forward with analysis)`, It is calling [DuplicateToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken) API, now it's sure. 

![DUPToken](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/Duplicate_token.png)


### Q4. What is the size (in bytes) of the XOR-obfuscated configuration data?

---> for this if we look below few lines below the where we found answer to above question, we can seee that there is a function worth looking into. 

![Xorfunc](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/xor_FUNC.png)

if we look inside of this function we can see it is obfuscating data using xor inside do while loop. (variable names may vary)

![insidexorfunc](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/xor_obfuscation.png)


### Q5. What process does the malware search for to steal access tokens?

--> for this question, i have already looked into it while answering Q.N.3. i.e. `explorer.exe` but, what with writup if it doesn't explain how. 

after that conditional check, if we look into the same function where [DuplicateToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken) API was called. We can see a function is being called, I have renamed it to something understandble to me however, logic doesn't change. 

![snapprocessfileter](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/snap_processfilter.png)

if we look inside that function it is calling [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) and takes snapshot of running processes on system. then uses [Process32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstW) and [Process32NextW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextW) to iterate one by one after captrued process. then widechar string compare is being done with `explorer.exe`. well this answers the question. 


![processfilter](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/process_filter.png)


### Q6. What year does the malware set when timestomping files?

Whie moving forward with analysis, looking on function call tree, few known win API were there, responsible for file time. Peeking on that function reveals, it is using [GetLocalTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlocaltime) to retrive current date and time then it had altered `wyear` to `0x7db` i.e. `2011` and used [SetFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime) for time stomping and setting the year to `2011`. 
![timestomping](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/timestomping.png)



### Q7. What is the hardcoded fallback DNS server IP address used for public IP discovery?

Looking for this question I have reached to a point, and to be honest I can't backtrace this, where have I reached and how I did that.

In this place on below screenshot, DNS `8.8.8.8` is hardcoded in it and this is our answer. 

![DNS](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/DNS.png)

For the backtrace, relying on Function call tree on ghidra is great. After taking look on that, Now I am sure where in the land am I. 

![function_tree](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/backtrace.png)

### Q8. What string does the malware log when the ICMP traceroute completes?

while following through above question about DNS. We can see it is opening a handle using [IcmpCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpcreatefile) API to open a handle then it uses [IcmpSendEcho](https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho) to repeatedly send ICMP Echo request using do while loop. 

![ICMPrequest](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/ICMPrequests.png)

while sending ICMP Echo request, it is incrementing `TTL` value to log all ip address while reaching to destination address i.e. `8.8.8.8`. By increasing TTL one hop at a time, it discovers each hop between the host and the destination. Then it logs ip addresses and finally when it reaches the destination address it logs, `Trace Complete.` and breaks the loop. 

![traceroute](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/trace_route.png)

### Q9. What is the maximum total operation time (in minutes) for the C2 beacon loop?

Answer to this question is `720` minutes. This thing was calculated by a well known chatbot. However, if this was in real world scenario then one couldn’t rely just on this. `Let’s do it the hard way.`

First of all, if we watch the function call tree for the function responsible for `Trace Route`, we can see the below.  
![Traceroutebacktrace](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/trace_route_backtrace.png)

On those functions, if we take a look at function `FUN_180002884`, which was invoked from `MainEntry` (only exported function of DLL). If we take a deeper look at that, that function is responsible for the rest of the jobs done by the malware. Even in our previous question, `Q8`, this function was in the call tree.

While looking at that function, there is an infinite `do...while(true)` loop in it, which could only return if a variable is greater than `0x2cf`, which is `719` in decimal, meaning that variable has to be a minimum of `720`, which is our answer so far.

![timecalculation](/FOLDSAB.github.io/assets/img/Sagerunex_analysis/time_calulation.png)

`However, we haven't still figured out why that variable is the time that we need.`

I have renamed `ivar26` to `breaker`. Please look out for that name below. We are going to call that variable `breaker` from now on.

Initially, the `breaker` is `0` and it is only used after the initialization, as seen in the screenshot above, when a condition is checked against it. So, we need to look for another variable i.e. `time` (names may vary). It has been used multiple times inside the loop; however, the only thing we have to compare it with is the C2 beacon.

The line of code responsible for the beacon lies in function `FUN_18000339c`, which can be seen in the screenshot below, which reveals (well, that is how I guessed).  

![beaconfunccode](/assets/img/Sagerunex_analysis/calltreebeacon.png)

Let’s get back to our `do...while(true)` loop. The function `FUN_18000339c` is called after meeting various conditions for the malware. When it reaches the point of calling, the beacon starts.

![beaconstarts](/assets/img/Sagerunex_analysis/beacon_starts.png)

If the function succeeds, then the value of `time` is set to `0x1e`, i.e. `30` in decimal. Then `WaitForSingleObject` is called with the parameter `dwMilliseconds` as `time * 60000`. This means the program is going to wait, or hold execution for `30 min * 60000 milliseconds`, i.e. 30 minutes. After that, the value is added to `breaker`, and the condition is checked: `if (0x2cf < breaker)`. This means the whole beacon has to continue for `(30 min * 24 times)` minutes just to make `breaker` greater than `0x2cf`.

![timecalculated](/assets/img/Sagerunex_analysis/time_waitforsignal.png)


### Q10. How many C2 servers does the malware cycle through?

The answer to this question is `5`.

From the previous question, we understood how the C2 beacon timing works. Inside that logic, the beacon function `FUN_18000339c` is called from inside a while loop.

![while_loop](/assets/img/Sagerunex_analysis/while_loop_for_beacon.png)

If we take a closer look at the code, `ivar20` is assigned using:

```c
ivar20 = time % 5;
```

Using the modulo operator `% 5` means the value of `ivar20` can only be:

```c
0, 1, 2, 3, 4
```

This gives a total of 5 possible values. These values are used as indexes for selecting the C2 servers, which means the malware cycles through 5 different C2 servers.

The while loop itself keeps running continuously because the calculated condition always evaluates to true:

```c
ivar1 = ivar20 - (ivar20 + 5)
       = -5
```

Since `ivar1` is always `< 0` , the condition `ivar1 < 0` is always true, allowing the beacon loop to continue running.


