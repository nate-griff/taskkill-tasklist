# Taskkill-Tasklist
Recreates a lightweight version of Window's taskkill and tasklist using Win32 API. Project for GMU DFOR 740.

## Usage

### Tasklist

Basic usage:

```powershell
tasklist.exe
tasklist.exe /V
tasklist.exe /SVC
tasklist.exe /?
```

Syntax:

```text
TASKLIST [/SVC | /V] [/?]
```

Options:

| Option | Description |
| --- | --- |
| `/SVC` | Displays services hosted in each process. |
| `/V` | Displays verbose task information (status, user, CPU time, window title). |
| `/?` | Displays help/usage text. |

Notes:

- `/V` and `/SVC` cannot be used together.
- Running with no options prints the default process table.

Basic example output:

```text
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0         8 K
System                           4 Services                   0     1,204 K
explorer.exe                  8420 Console                    1    95,432 K
notepad.exe                  12644 Console                    1     8,600 K
```

Verbose example output:

```text
Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title
========================= ======== ================ =========== ============ =============== ================================================== ============ =======================================================================
explorer.exe                  8420 Console                    1    95,432 K RUNNING         DESKTOP\nate                                         000:02:13 File Explorer
notepad.exe                  12644 Console                    1     8,600 K RUNNING         DESKTOP\nate                                         000:00:02 notes.txt - Notepad
```

Services view example output:

```text
Image Name                     PID Services
========================= ======== ===========================================
svchost.exe                   1048 DcomLaunch, PlugPlay, Power
svchost.exe                   1132 RpcEptMapper, RpcSs
```

### Taskkill

Basic usage:

```powershell
taskkill.exe /PID 12644
taskkill.exe /IM notepad.exe
taskkill.exe /F /IM notepad.exe /T
taskkill.exe /S server01 /U DOMAIN\admin /P /PID 8080
taskkill.exe /?
```

Syntax:

```text
TASKKILL [/S system [/U username [/P [password]]]]
         { [/PID processid | /IM imagename] } [/T] [/F] [/?]
```

Options:

| Option | Description |
| --- | --- |
| `/PID <processid>` | Terminates a process by PID. Can be specified multiple times. |
| `/IM <imagename>` | Terminates by image name (supports `*` and `?` wildcards). Can be specified multiple times. |
| `/F` | Forcefully terminates process(es). |
| `/T` | Terminates the target process and child processes. |
| `/S <system>` | Specifies a remote system. |
| `/U <[domain\]user>` | User context for remote operations. Requires `/S`. |
| `/P [password]` | Password for `/U`. If omitted after `/P`, tool prompts interactively. Requires `/U` and `/S`. |
| `/?` | Displays help/usage text. |

Notes:

- At least one `/PID` or `/IM` must be provided.
- `/U` and `/P` are valid only when `/S` is used.

Basic example output:

```text
SUCCESS: Sent termination signal to the process "notepad.exe" with PID 12644.
```

Forced/tree example output:

```text
SUCCESS: The process with PID 13220 (child process of PID 12644) has been terminated.
SUCCESS: The process "notepad.exe" with PID 12644 has been terminated.
```

Basic error example output:

```text
ERROR: The process "missing.exe" not found.
```

## Tasklist
### Win32 API Headers Used
<details>
<summary><strong><code>windows.h</code></strong></summary>

- Base Win32 API types, constants, and process/window/service helpers.
- Functions used:
    - `GetLastError`
    - `CloseHandle`
    - `GetWindowThreadProcessId`
    - `IsWindowVisible`
    - `GetWindowTextLengthW`
    - `GetWindowTextW`
    - `EnumWindows`
    - `OpenSCManagerW`
    - `EnumServicesStatusExW`
    - `CloseServiceHandle`
    - `ProcessIdToSessionId`
    - `OpenProcess`
    - `GetProcessTimes`
    - `OpenProcessToken`
    - `GetTokenInformation`
    - `LookupAccountSidW`

</details>

<details>
<summary><strong><code>tlhelp32.h</code></strong></summary>

- Tool Help snapshot APIs for enumerating running processes.
- Functions used:
    - `CreateToolhelp32Snapshot`
    - `Process32FirstW`
    - `Process32NextW`

</details>

<details>
<summary><strong><code>psapi.h</code></strong></summary>

- Process Status API for process memory statistics.
- Functions used:
    - `GetProcessMemoryInfo`

</details>

<details>
<summary><strong><code>wtsapi32.h</code></strong></summary>

- Windows Terminal Services APIs for session metadata.
- Functions used:
    - `WTSQuerySessionInformationW`
    - `WTSFreeMemory`

</details>

## Taskkill
### Win32 API Headers Used
<details>
<summary><strong><code>windows.h</code></strong></summary>

- Core Win32 process, token, console, and error handling APIs.
- Functions used:
    - `CloseHandle`
    - `GetLastError`
    - `FormatMessageW`
    - `LocalFree`
    - `GetStdHandle`
    - `GetConsoleMode`
    - `SetConsoleMode`
    - `LogonUserW`
    - `ImpersonateLoggedOnUser`
    - `RevertToSelf`
    - `OpenProcess`
    - `QueryFullProcessImageNameW`
    - `TerminateProcess`

</details>

<details>
<summary><strong><code>tlhelp32.h</code></strong></summary>

- Tool Help snapshot APIs for local process enumeration.
- Functions used:
    - `CreateToolhelp32Snapshot`
    - `Process32FirstW`
    - `Process32NextW`

</details>

<details>
<summary><strong><code>wtsapi32.h</code></strong></summary>

- Windows Terminal Services APIs for remote process management.
- Functions used:
    - `WTSOpenServerW`
    - `WTSCloseServer`
    - `WTSEnumerateProcessesExW`
    - `WTSFreeMemoryExW`
    - `WTSTerminateProcess`

</details>

<details>
<summary><strong><code>pdh.h</code></strong></summary>

- Performance Data Helper APIs for reading remote process counters.
- Functions used:
    - `PdhOpenQueryW`
    - `PdhAddEnglishCounterW`
    - `PdhCollectQueryData`
    - `PdhGetFormattedCounterArrayW`
    - `PdhCloseQuery`

</details>

<details>
<summary><strong><code>pdhmsg.h</code></strong></summary>

- PDH status and message constants used with PDH return codes.
- Functions used:
    - No direct function calls from this header.

</details>
