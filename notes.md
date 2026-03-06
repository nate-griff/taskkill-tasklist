# Tasklist
## Assignment Requirements
Rebuild the tasklist binary for CLI in C++ only using win32api 
Only required to rebuild with /V and /SVC
I want to add a /? that shows the basic usage `TASKLIST [/SVC | /V] [/?]`, Description, Parameter list, and Examples
## Full /? output
```
tasklist /?

TASKLIST [/S system [/U username [/P [password]]]]
         [/M [module] | /SVC | /V] [/FI filter] [/FO format] [/NH]

Description:
    This tool displays a list of currently running processes on
    either a local or remote machine.

Parameter List:
   /S     system           Specifies the remote system to connect to.

   /U     [domain\]user    Specifies the user context under which
                           the command should execute.

   /P     [password]       Specifies the password for the given
                           user context. Prompts for input if omitted.

   /M     [module]         Lists all tasks currently using the given
                           exe/dll name. If the module name is not
                           specified all loaded modules are displayed.

   /SVC                    Displays services hosted in each process.

   /APPS                   Displays Store Apps and their associated processes.

   /V                      Displays verbose task information.

   /FI    filter           Displays a set of tasks that match a
                           given criteria specified by the filter.

   /FO    format           Specifies the output format.
                           Valid values: "TABLE", "LIST", "CSV".

   /NH                     Specifies that the "Column Header" should
                           not be displayed in the output.
                           Valid only for "TABLE" and "CSV" formats.

   /?                      Displays this help message.

Filters:
    Filter Name     Valid Operators           Valid Value(s)
    -----------     ---------------           --------------------------
    STATUS          eq, ne                    RUNNING | SUSPENDED
                                              NOT RESPONDING | UNKNOWN
    IMAGENAME       eq, ne                    Image name
    PID             eq, ne, gt, lt, ge, le    PID value
    SESSION         eq, ne, gt, lt, ge, le    Session number
    SESSIONNAME     eq, ne                    Session name
    CPUTIME         eq, ne, gt, lt, ge, le    CPU time in the format
                                              of hh:mm:ss.
                                              hh - hours,
                                              mm - minutes, ss - seconds
    MEMUSAGE        eq, ne, gt, lt, ge, le    Memory usage in KB
    USERNAME        eq, ne                    User name in [domain\]user
                                              format
    SERVICES        eq, ne                    Service name
    WINDOWTITLE     eq, ne                    Window title
    MODULES         eq, ne                    DLL name

NOTE: "WINDOWTITLE" and "STATUS" filters are not supported when querying
      a remote machine.

Examples:
    TASKLIST
    TASKLIST /M
    TASKLIST /V /FO CSV
    TASKLIST /SVC /FO LIST
    TASKLIST /APPS /FI "STATUS eq RUNNING"
    TASKLIST /M wbem*
    TASKLIST /S system /FO LIST
    TASKLIST /S system /U domain\username /FO CSV /NH
    TASKLIST /S system /U username /P password /FO TABLE /NH
    TASKLIST /FI "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running"
```
## Format/Output
```
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
25 char name.exe          rbound # Services/Console    rbound # rb ###,### K
```
By default, `tasklist` prints one by one, it doesn't wait for full list then block prints, it prints sequentially
Image name gets cut to 25 characters
Order looks sequential by PID, but not fully consistent, so maybe just how win32 api processes them in order
### /V format
```
Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title                                        
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
```
Looks the same spacing as default, but has status (14 Char response max), User Name (49 Char max), CPU time (right bound hhh:mm:ss), Window Title (71 Char max)
### /SVC format
```
Image Name                     PID Services
========================= ======== ============================================
25 char name.exe          rbound # Service1, Service2, etc, 43 char width wrap
                                   to next line
```
## Structure thoughts
Start with input processing
- Can handle upper and lowercase variables (e.g. `/v` or `/V` both do verbose)
- Handles extra spaces (e.g. `tasklist  /v` doesn't break with 2 spaces)
- /V and /SVC cannot be used together. If seen, print `ERROR: Invalid syntax. /V, /M and /SVC options cannot be used together.\nType "TASKLIST /?" for usage.`
Grab list of all processes
Print header based on input options
Loop through all processes and send them to function that gets the data and prints it with formatting
- each process gets a function call
- This helps it process real time (helpful for /V which takes a while to load details)
Cleanup after the loop is done
Exit
## Win32 APIs of Interest
tlhelp32.h
- CreateToolhelp32Snapshot
- Process32First
- Process32Next
- PROCESSENTRY32 structure
processthreadsapi.h
- GetProcessId
- GetSystemTimes (not sure about this one)
# Taskkill
## Assignment Requirements
Rebuild the taskkill binary for CLI in C++ only using win32api 
Only required to rebuild with /PID, /IM, /F, /S, /U, and /T
I want to add a /? that shows the basic usage, Description, Parameter list, and Examples
## Full /? output
```
taskkill /?

TASKKILL [/S system [/U username [/P [password]]]]
         { [/FI filter] [/PID processid | /IM imagename] } [/T] [/F]

Description:
    This tool is used to terminate tasks by process id (PID) or image name.

Parameter List:
    /S    system           Specifies the remote system to connect to.

    /U    [domain\]user    Specifies the user context under which the
                           command should execute.

    /P    [password]       Specifies the password for the given user
                           context. Prompts for input if omitted.

    /FI   filter           Applies a filter to select a set of tasks.
                           Allows "*" to be used. ex. imagename eq acme*

    /PID  processid        Specifies the PID of the process to be terminated.
                           Use TaskList to get the PID.

    /IM   imagename        Specifies the image name of the process
                           to be terminated. Wildcard '*' can be used
                           to specify all tasks or image names.

    /T                     Terminates the specified process and any
                           child processes which were started by it.

    /F                     Specifies to forcefully terminate the process(es).

    /?                     Displays this help message.

Filters:
    Filter Name   Valid Operators           Valid Value(s)
    -----------   ---------------           -------------------------
    STATUS        eq, ne                    RUNNING |
                                            NOT RESPONDING | UNKNOWN
    IMAGENAME     eq, ne                    Image name
    PID           eq, ne, gt, lt, ge, le    PID value
    SESSION       eq, ne, gt, lt, ge, le    Session number.
    CPUTIME       eq, ne, gt, lt, ge, le    CPU time in the format
                                            of hh:mm:ss.
                                            hh - hours,
                                            mm - minutes, ss - seconds
    MEMUSAGE      eq, ne, gt, lt, ge, le    Memory usage in KB
    USERNAME      eq, ne                    User name in [domain\]user
                                            format
    MODULES       eq, ne                    DLL name
    SERVICES      eq, ne                    Service name
    WINDOWTITLE   eq, ne                    Window title

    NOTE
    ----
    1) Wildcard '*' for /IM switch is accepted only when a filter is applied.
    2) Termination of remote processes will always be done forcefully (/F).
    3) "WINDOWTITLE" and "STATUS" filters are not considered when a remote
       machine is specified.

Examples:
    TASKKILL /IM notepad.exe
    TASKKILL /PID 1230 /PID 1241 /PID 1253 /T
    TASKKILL /F /IM cmd.exe /T
    TASKKILL /F /FI "PID ge 1000" /FI "WINDOWTITLE ne untitle*"
    TASKKILL /F /FI "USERNAME eq NT AUTHORITY\SYSTEM" /IM notepad.exe
    TASKKILL /S system /U domain\username /FI "USERNAME ne NT*" /IM *
    TASKKILL /S system /U username /P password /FI "IMAGENAME eq note*"
```
## Format/Output
### /PID
`SUCCESS: Sent termination signal to the process with PID ####.`
or
`ERROR: The process "####" not found.`
### /IM
for each matching imagename,
`SUCCESS: Sent termination signal to the process "{imagename}" with PID ####.`
or
`ERROR: The process "{imagename}" not found.`
### /F
Can be used with others to force kill, changes message to 
`SUCCESS: The process "{imagename}" with PID #### has been terminated.`
### /T
Reverse order, starting with all children then working up to the sent in process
For each process (PID flag given)
`SUCCESS: The process with PID #### (child process of PID ####) has been terminated.`
or 
```
ERROR: The process with PID #### (child process of PID ####) could not be terminated.
Reason: This process can only be terminated forcefully (with /F option).
```
or 
```
ERROR: The process with PID #### (child process of PID ####) could not be terminated.
Reason: One or more child processes of this process were still running.
```
(maybe more errors but these were the ones I ran into)
Also there are options with imagename, but those are basically the same, just slight syntax updates
### /U
For specific user, terminate that process
Not sure how to test the format/output since I'm on a single user computer
### /S 
For remote system, can send in hostname or IP
Again, not sure how to test
Probably requires both /U and /P for username and password
## Structure Thoughts
Start with input processing
- Similar to tasklist, able to handle upper/lowercase and also extra spaces
- This one also requires more detailed input (flag, variable) for most inputs, so a way to parse that
- error handling for incompatible combinations (if any?)
If remote system, attempt connection
- If no /U or /P, make sure to give feedback that it may be a login issue
	- Check connection to host (does it exist)
	- If not, probably not a credentials issue
- Once connected, proceed with other flags to kill requested process
Handle inputs to search for process either by PID or imagename
If found and /T flag given, search for subprocesses, otherwise throw error
send termination signal(s) (or force termination(s) if /F sent)
Listen for feedback and handle errors
## Win32 APIs of Interest
tlhelp32.h
- CreateToolhelp32Snapshot
- Process32First
- Process32Next
- PROCESSENTRY32 structure
processthreadsapi.h
- TerminateProcess
- ExitProcess
- GetProcessId
