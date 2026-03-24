#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <tlhelp32.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <cwctype>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Wtsapi32.lib")

namespace {

// Parsed command-line switches for local and remote termination scenarios.
struct Options {
    bool showHelp = false;
    bool force = false;
    bool tree = false;
    bool promptForPassword = false;
    std::wstring remoteSystem;
    std::wstring user;
    std::wstring password;
    std::vector<DWORD> pids;
    std::vector<std::wstring> imageNames;
};

// Minimal process model used for matching targets and building /T child maps.
struct ProcessInfo {
    DWORD pid = 0;
    DWORD parentPid = 0;
    std::wstring imageName;
};

std::wstring FormatSystemMessage(DWORD error);

// RAII wrapper for Win32 HANDLE values that use CloseHandle.
class ScopedHandle {
public:
    ScopedHandle() = default;

    explicit ScopedHandle(HANDLE handle)
        : handle_(handle) {
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept
        : handle_(other.release()) {
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    ~ScopedHandle() {
        reset();
    }

    HANDLE get() const {
        return handle_;
    }

    void reset(HANDLE handle = nullptr) {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

    HANDLE release() {
        HANDLE handle = handle_;
        handle_ = nullptr;
        return handle;
    }

private:
    HANDLE handle_ = nullptr;
};

// RAII wrapper for WTS server handles that use WTSCloseServer.
class ScopedWtsServerHandle {
public:
    ScopedWtsServerHandle() = default;

    explicit ScopedWtsServerHandle(HANDLE handle)
        : handle_(handle) {
    }

    ScopedWtsServerHandle(const ScopedWtsServerHandle&) = delete;
    ScopedWtsServerHandle& operator=(const ScopedWtsServerHandle&) = delete;

    ~ScopedWtsServerHandle() {
        reset();
    }

    HANDLE get() const {
        return handle_;
    }

    void reset(HANDLE handle = nullptr) {
        if (handle_) {
            WTSCloseServer(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

// RAII guard that reverts impersonation on scope exit.
class ScopedImpersonation {
public:
    ScopedImpersonation() = default;
    ScopedImpersonation(const ScopedImpersonation&) = delete;
    ScopedImpersonation& operator=(const ScopedImpersonation&) = delete;

    ~ScopedImpersonation() {
        if (active_) {
            RevertToSelf();
        }
    }

    bool Begin(HANDLE token, std::wstring& errorMessage) {
        if (!token) {
            errorMessage = L"No logon token was created.";
            return false;
        }

        token_.reset(token);
        if (!ImpersonateLoggedOnUser(token_.get())) {
            errorMessage = L"ImpersonateLoggedOnUser failed: " + FormatSystemMessage(GetLastError());
            token_.reset();
            return false;
        }

        active_ = true;
        return true;
    }

private:
    ScopedHandle token_;
    bool active_ = false;
};

// Normalize command-line switches to uppercase for case-insensitive parsing.
std::wstring ToUpper(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towupper(c)); });
    return value;
}

// Accept either SERVER or \\SERVER forms and normalize to SERVER.
std::wstring NormalizeRemoteSystemName(std::wstring value) {
    while (value.rfind(L"\\\\", 0) == 0) {
        value.erase(0, 2);
    }
    return value;
}

// Convert a Win32 error code into a trimmed, human-readable message.
std::wstring FormatSystemMessage(DWORD error) {
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring message = length != 0 && buffer ? buffer : L"Unknown error.";
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || std::iswspace(message.back()))) {
        message.pop_back();
    }

    if (buffer) {
        LocalFree(buffer);
    }

    return message;
}

// Split DOMAIN\\User into separate components for LogonUserW.
void SplitAccountName(const std::wstring& accountName, std::wstring& domain, std::wstring& userName) {
    const size_t slash = accountName.find(L'\\');
    if (slash == std::wstring::npos) {
        domain.clear();
        userName = accountName;
        return;
    }

    domain = accountName.substr(0, slash);
    userName = accountName.substr(slash + 1);
}

// Read a password from the console while disabling local echo.
bool PromptForPassword(const std::wstring& userName, std::wstring& password) {
    std::wcout << L"Type the password for " << userName << L": ";

    const HANDLE inputHandle = GetStdHandle(STD_INPUT_HANDLE);
    DWORD originalMode = 0;
    const bool hasConsoleMode = inputHandle != nullptr &&
        inputHandle != INVALID_HANDLE_VALUE &&
        GetConsoleMode(inputHandle, &originalMode) != FALSE;

    if (hasConsoleMode) {
        SetConsoleMode(inputHandle, originalMode & ~ENABLE_ECHO_INPUT);
    }

    const bool readSucceeded = static_cast<bool>(std::getline(std::wcin, password));

    if (hasConsoleMode) {
        SetConsoleMode(inputHandle, originalMode);
    }

    std::wcout << L"\n";
    return readSucceeded;
}

// Create an impersonation token for remote operations when /U is supplied.
bool CreateRemoteLogonToken(const Options& options, ScopedHandle& token, std::wstring& errorMessage) {
    // No explicit remote user means we keep the current security context.
    if (options.user.empty()) {
        return true;
    }

    // /P can be omitted, in which case we ask interactively.
    std::wstring password = options.password;
    if (options.promptForPassword && !PromptForPassword(options.user, password)) {
        errorMessage = L"Could not read the password from the console.";
        return false;
    }

    std::wstring domain;
    std::wstring userName;
    SplitAccountName(options.user, domain, userName);
    if (userName.empty()) {
        errorMessage = L"ERROR: Invalid value supplied for /U.";
        return false;
    }

    // LOGON32_LOGON_NEW_CREDENTIALS is typically used for network/remote access.
    HANDLE rawToken = nullptr;
    if (!LogonUserW(
            userName.c_str(),
            domain.empty() ? nullptr : domain.c_str(),
            password.c_str(),
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_WINNT50,
            &rawToken)) {
        errorMessage = L"LogonUserW failed: " + FormatSystemMessage(GetLastError());
        return false;
    }

    token.reset(rawToken);
    return true;
}

// Recursive wildcard matcher that supports `*` and `?`.
bool WildcardMatchRecursive(const wchar_t* pattern, const wchar_t* text) {
    // Base case: a finished pattern only matches a finished text.
    if (*pattern == L'\0') {
        return *text == L'\0';
    }

    if (*pattern == L'*') {
        // `*` can match zero chars (pattern+1) or one+ chars (text+1).
        return WildcardMatchRecursive(pattern + 1, text) || (*text != L'\0' && WildcardMatchRecursive(pattern, text + 1));
    }

    if (*pattern == L'?') {
        // `?` matches exactly one character.
        return *text != L'\0' && WildcardMatchRecursive(pattern + 1, text + 1);
    }

    // Regular character match is case-insensitive.
    return std::towupper(*pattern) == std::towupper(*text) && WildcardMatchRecursive(pattern + 1, text + 1);
}

// Case-insensitive wildcard match wrapper for image names.
bool WildcardMatch(const std::wstring& pattern, const std::wstring& text) {
    return WildcardMatchRecursive(pattern.c_str(), text.c_str());
}

// Print command-line help similar to the Windows taskkill utility.
void PrintHelp() {
    std::wcout << L"TASKKILL [/S system [/U username [/P [password]]]]\n";
    std::wcout << L"         { [/PID processid | /IM imagename] } [/T] [/F] [/?]\n\n";
    std::wcout << L"Description:\n";
    std::wcout << L"    Terminates tasks by process ID (PID) or image name.\n\n";
    std::wcout << L"Parameter List:\n";
    std::wcout << L"    /PID  processid        Specifies the PID of the process to terminate.\n";
    std::wcout << L"    /IM   imagename        Specifies the image name to terminate (supports * and ?).\n";
    std::wcout << L"    /F                     Forcefully terminates the process(es).\n";
    std::wcout << L"    /T                     Terminates the process and child processes.\n";
    std::wcout << L"    /S    system           Specifies remote system to connect to.\n";
    std::wcout << L"    /U    [domain\\]user    Specifies user context for remote execution.\n";
    std::wcout << L"    /P    [password]       Specifies password for the given user.\n";
    std::wcout << L"    /?                     Displays this help message.\n\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"    TASKKILL /IM notepad.exe\n";
    std::wcout << L"    TASKKILL /PID 1230 /T\n";
    std::wcout << L"    TASKKILL /F /IM cmd.exe /T\n";
}

// Parse and validate a PID argument as a non-zero decimal value.
bool ParsePid(const std::wstring& value, DWORD& pid) {
    if (value.empty()) {
        return false;
    }

    wchar_t* end = nullptr;
    const unsigned long parsed = wcstoul(value.c_str(), &end, 10);
    if (*end != L'\0') {
        return false;
    }

    pid = static_cast<DWORD>(parsed);
    return pid != 0;
}

// Parse supported taskkill switches and enforce switch dependencies.
bool ParseArgs(int argc, wchar_t* argv[], Options& options) {
    for (int i = 1; i < argc; ++i) {
        // All switch checks are case-insensitive.
        const std::wstring argUpper = ToUpper(argv[i]);

        if (argUpper == L"/?") {
            options.showHelp = true;
            continue;
        }

        if (argUpper == L"/F") {
            options.force = true;
            continue;
        }

        if (argUpper == L"/T") {
            options.tree = true;
            continue;
        }

        if (argUpper == L"/PID") {
            if (i + 1 >= argc) {
                std::wcout << L"ERROR: Missing value for /PID.\n";
                return false;
            }

            // Consume the next token as the PID value.
            DWORD pid = 0;
            if (!ParsePid(argv[++i], pid)) {
                std::wcout << L"ERROR: Invalid PID value: " << argv[i] << L"\n";
                return false;
            }
            options.pids.push_back(pid);
            continue;
        }

        if (argUpper == L"/IM") {
            if (i + 1 >= argc) {
                std::wcout << L"ERROR: Missing value for /IM.\n";
                return false;
            }
            options.imageNames.emplace_back(argv[++i]);
            continue;
        }

        if (argUpper == L"/S") {
            if (i + 1 >= argc) {
                std::wcout << L"ERROR: Missing value for /S.\n";
                return false;
            }
            options.remoteSystem = argv[++i];
            continue;
        }

        if (argUpper == L"/U") {
            if (i + 1 >= argc) {
                std::wcout << L"ERROR: Missing value for /U.\n";
                return false;
            }
            options.user = argv[++i];
            continue;
        }

        if (argUpper == L"/P") {
            // /P with no value means prompt securely at runtime.
            if (i + 1 < argc && argv[i + 1][0] != L'/') {
                options.password = argv[++i];
                options.promptForPassword = false;
            }
            else {
                options.password.clear();
                options.promptForPassword = true;
            }
            continue;
        }

        std::wcout << L"ERROR: Invalid argument: " << argv[i] << L"\n";
        return false;
    }

    if (!options.showHelp && options.pids.empty() && options.imageNames.empty()) {
        std::wcout << L"ERROR: At least one /PID or /IM must be specified.\n";
        return false;
    }

    // Normalize remote host syntax before validating dependent switches.
    options.remoteSystem = NormalizeRemoteSystemName(options.remoteSystem);

    if (options.remoteSystem.empty() && (!options.user.empty() || !options.password.empty() || options.promptForPassword)) {
        std::wcout << L"ERROR: /U and /P can only be used together with /S.\n";
        return false;
    }

    if (options.remoteSystem.empty() == false && options.promptForPassword && options.user.empty()) {
        std::wcout << L"ERROR: /P requires /U to be specified.\n";
        return false;
    }

    if (options.remoteSystem.empty() == false && !options.password.empty() && options.user.empty()) {
        std::wcout << L"ERROR: /P requires /U to be specified.\n";
        return false;
    }

    if (!options.remoteSystem.empty() && options.remoteSystem == L".") {
        options.remoteSystem.clear();
    }

    return true;
}

// Build a local process snapshot with parent PID relationships.
std::vector<ProcessInfo> EnumerateLocalProcesses() {
    std::vector<ProcessInfo> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            ProcessInfo process;
            process.pid = entry.th32ProcessID;
            process.parentPid = entry.th32ParentProcessID;
            process.imageName = entry.szExeFile;
            processes.push_back(std::move(process));
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processes;
}

// Generic PDH array item used for both PID and parent-PID counters.
struct CounterValue {
    std::wstring instanceName;
    LONGLONG value = 0;
};

// Read an instance-based PDH counter into a simple C++ vector.
bool ReadFormattedCounterArray(HCOUNTER counter, std::vector<CounterValue>& values) {
    // First PDH call asks for the required buffer size.
    DWORD bufferSize = 0;
    DWORD itemCount = 0;
    PDH_STATUS status = PdhGetFormattedCounterArrayW(counter, PDH_FMT_LARGE, &bufferSize, &itemCount, nullptr);
    if (status != PDH_MORE_DATA) {
        return false;
    }

    // Second call reads the actual counter items into the allocated buffer.
    std::vector<BYTE> buffer(bufferSize);
    auto* items = reinterpret_cast<PPDH_FMT_COUNTERVALUE_ITEM_W>(buffer.data());
    status = PdhGetFormattedCounterArrayW(counter, PDH_FMT_LARGE, &bufferSize, &itemCount, items);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    values.clear();
    values.reserve(itemCount);
    for (DWORD i = 0; i < itemCount; ++i) {
        if (items[i].FmtValue.CStatus != ERROR_SUCCESS) {
            continue;
        }

        CounterValue value;
        value.instanceName = items[i].szName ? items[i].szName : L"";
        value.value = items[i].FmtValue.largeValue;
        values.push_back(std::move(value));
    }

    return true;
}

// Query remote performance counters to recover parent PID relationships.
bool PopulateRemoteParentPids(const std::wstring& remoteSystem, std::vector<ProcessInfo>& processes, std::wstring& errorMessage) {
    HQUERY query = nullptr;
    if (PdhOpenQueryW(nullptr, 0, &query) != ERROR_SUCCESS) {
        errorMessage = L"PdhOpenQueryW failed.";
        return false;
    }

    HCOUNTER pidCounter = nullptr;
    HCOUNTER parentCounter = nullptr;
    const std::wstring pidPath = L"\\\\" + remoteSystem + L"\\Process(*)\\ID Process";
    const std::wstring parentPath = L"\\\\" + remoteSystem + L"\\Process(*)\\Creating Process ID";

    // Add both counters to a single query so one collect gives aligned samples.
    const PDH_STATUS pidStatus = PdhAddEnglishCounterW(query, pidPath.c_str(), 0, &pidCounter);
    const PDH_STATUS parentStatus = PdhAddEnglishCounterW(query, parentPath.c_str(), 0, &parentCounter);
    if (pidStatus != ERROR_SUCCESS || parentStatus != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        errorMessage = L"Could not query remote process performance counters.";
        return false;
    }

    const PDH_STATUS collectStatus = PdhCollectQueryData(query);
    if (collectStatus != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        errorMessage = L"PdhCollectQueryData failed.";
        return false;
    }

    std::vector<CounterValue> pidValues;
    std::vector<CounterValue> parentValues;
    const bool pidRead = ReadFormattedCounterArray(pidCounter, pidValues);
    const bool parentRead = ReadFormattedCounterArray(parentCounter, parentValues);
    PdhCloseQuery(query);

    if (!pidRead || !parentRead) {
        errorMessage = L"Could not read remote process performance counter data.";
        return false;
    }

    // PDH instance names are not unique, so align entries by occurrence index.
    std::map<std::wstring, std::vector<size_t>> parentIndexesByName;
    for (size_t i = 0; i < parentValues.size(); ++i) {
        parentIndexesByName[parentValues[i].instanceName].push_back(i);
    }

    std::map<std::wstring, size_t> nextParentIndexByName;
    std::map<DWORD, DWORD> parentsByPid;
    for (const CounterValue& pidValue : pidValues) {
        if (pidValue.value == 0) {
            continue;
        }

        const auto it = parentIndexesByName.find(pidValue.instanceName);
        if (it == parentIndexesByName.end()) {
            continue;
        }

        size_t& nextIndex = nextParentIndexByName[pidValue.instanceName];
        if (nextIndex >= it->second.size()) {
            continue;
        }

        const CounterValue& parentValue = parentValues[it->second[nextIndex++]];
        // Build a direct PID -> parent PID lookup for fast later assignment.
        parentsByPid[static_cast<DWORD>(pidValue.value)] = static_cast<DWORD>(parentValue.value);
    }

    for (ProcessInfo& process : processes) {
        const auto it = parentsByPid.find(process.pid);
        if (it != parentsByPid.end()) {
            process.parentPid = it->second;
        }
    }

    return true;
}

// Enumerate remote processes through WTS and optionally enrich with parent PIDs.
bool EnumerateRemoteProcesses(HANDLE serverHandle, const std::wstring& remoteSystem, bool includeParentPids, std::vector<ProcessInfo>& processes, std::wstring& errorMessage) {
    processes.clear();

    DWORD level = 1;
    DWORD count = 0;
    PWTS_PROCESS_INFO_EXW processInfo = nullptr;
    if (!WTSEnumerateProcessesExW(serverHandle, &level, WTS_ANY_SESSION, reinterpret_cast<LPWSTR*>(&processInfo), &count)) {
        errorMessage = L"WTSEnumerateProcessesExW failed: " + FormatSystemMessage(GetLastError());
        return false;
    }

    for (DWORD i = 0; i < count; ++i) {
        ProcessInfo process;
        process.pid = processInfo[i].ProcessId;
        process.imageName = processInfo[i].pProcessName ? processInfo[i].pProcessName : L"";
        processes.push_back(std::move(process));
    }

    WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, processInfo, count);

    if (includeParentPids && !PopulateRemoteParentPids(remoteSystem, processes, errorMessage)) {
        return false;
    }

    return true;
}

// Produce a post-order termination list so children are killed before parents.
std::vector<DWORD> BuildTreeOrder(
    DWORD rootPid,
    const std::map<DWORD, std::vector<DWORD>>& childrenByParent,
    std::set<DWORD>& visited) {

    // Post-order traversal: descend first so children are terminated first.
    std::vector<DWORD> order;
    if (!visited.insert(rootPid).second) {
        return order;
    }

    const auto it = childrenByParent.find(rootPid);
    if (it != childrenByParent.end()) {
        for (const DWORD childPid : it->second) {
            std::vector<DWORD> childOrder = BuildTreeOrder(childPid, childrenByParent, visited);
            order.insert(order.end(), childOrder.begin(), childOrder.end());
        }
    }

    order.push_back(rootPid);
    return order;
}

// Terminate one local PID and optionally return its image name.
bool TerminateLocalPid(DWORD pid, bool force, std::wstring* imageOut = nullptr) {
    // Need terminate rights; query rights allow optional image-name lookup.
    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!processHandle) {
        return false;
    }

    if (imageOut) {
        WCHAR imageName[MAX_PATH] = {};
        DWORD size = static_cast<DWORD>(std::size(imageName));
        if (QueryFullProcessImageNameW(processHandle, 0, imageName, &size)) {
            std::wstring fullPath(imageName);
            const size_t slash = fullPath.find_last_of(L"\\/");
            *imageOut = slash == std::wstring::npos ? fullPath : fullPath.substr(slash + 1);
        }
    }

    const BOOL result = TerminateProcess(processHandle, force ? 1 : 0);
    CloseHandle(processHandle);
    return result == TRUE;
}

// Terminate one remote PID through the WTS API.
bool TerminateRemotePid(HANDLE serverHandle, DWORD pid, bool force) {
    return WTSTerminateProcess(serverHandle, pid, force ? 1u : 0u) == TRUE;
}

// Resolve explicit /PID targets plus any /IM wildcard matches.
std::vector<DWORD> ResolveTargetPids(const Options& options, const std::vector<ProcessInfo>& processes) {
    std::set<DWORD> uniqueTargets(options.pids.begin(), options.pids.end());

    for (const std::wstring& imagePattern : options.imageNames) {
        for (const ProcessInfo& process : processes) {
            if (WildcardMatch(imagePattern, process.imageName)) {
                uniqueTargets.insert(process.pid);
            }
        }
    }

    return std::vector<DWORD>(uniqueTargets.begin(), uniqueTargets.end());
}

// Find process metadata for display messages.
const ProcessInfo* FindProcess(const std::vector<ProcessInfo>& processes, DWORD pid) {
    for (const ProcessInfo& process : processes) {
        if (process.pid == pid) {
            return &process;
        }
    }
    return nullptr;
}

// Main taskkill execution path for both local and remote systems.
int RunTaskkill(const Options& options) {
    const bool isRemote = !options.remoteSystem.empty();
    ScopedHandle remoteToken;
    ScopedImpersonation impersonation;
    ScopedWtsServerHandle serverHandle;

    std::vector<ProcessInfo> processes;
    if (isRemote) {
        // Remote mode can impersonate alternate credentials before opening WTS.
        std::wstring errorMessage;
        if (!CreateRemoteLogonToken(options, remoteToken, errorMessage)) {
            std::wcout << L"ERROR: " << errorMessage << L"\n";
            return 1;
        }

        if (remoteToken.get() && !impersonation.Begin(remoteToken.release(), errorMessage)) {
            std::wcout << L"ERROR: " << errorMessage << L"\n";
            return 1;
        }

        std::wstring serverName = options.remoteSystem;
        serverHandle.reset(WTSOpenServerW(serverName.data()));

        if (!serverHandle.get()) {
            std::wcout << L"ERROR: Could not connect to remote system \"" << options.remoteSystem
                       << L"\": " << FormatSystemMessage(GetLastError()) << L"\n";
            return 1;
        }

        if (!EnumerateRemoteProcesses(serverHandle.get(), options.remoteSystem, options.tree, processes, errorMessage)) {
            std::wcout << L"ERROR: Could not enumerate processes on remote system \"" << options.remoteSystem
                       << L"\": " << errorMessage << L"\n";
            return 1;
        }
    }
    else {
        processes = EnumerateLocalProcesses();
    }

    if (processes.empty()) {
        std::wcout << L"ERROR: Could not enumerate running processes.\n";
        return 1;
    }

    const std::vector<DWORD> targets = ResolveTargetPids(options, processes);
    if (targets.empty()) {
        // Mirror taskkill-like feedback for each explicit selector.
        for (const std::wstring& imageName : options.imageNames) {
            std::wcout << L"ERROR: The process \"" << imageName << L"\" not found.\n";
        }
        for (const DWORD pid : options.pids) {
            std::wcout << L"ERROR: The process \"" << pid << L"\" not found.\n";
        }
        return 1;
    }

    // Precompute parent -> children lists for /T termination ordering.
    std::map<DWORD, std::vector<DWORD>> childrenByParent;
    for (const ProcessInfo& process : processes) {
        childrenByParent[process.parentPid].push_back(process.pid);
    }

    int failures = 0;
    for (const DWORD target : targets) {
        std::vector<DWORD> order;
        if (options.tree) {
            std::set<DWORD> visited;
            order = BuildTreeOrder(target, childrenByParent, visited);
        }
        else {
            order.push_back(target);
        }

        // Execute termination in the computed order and print result per PID.
        for (const DWORD pid : order) {
            const ProcessInfo* processInfo = FindProcess(processes, pid);
            const std::wstring imageName = processInfo ? processInfo->imageName : L"UNKNOWN";

            const bool terminated = isRemote
                ? TerminateRemotePid(serverHandle.get(), pid, options.force)
                : TerminateLocalPid(pid, options.force, nullptr);

            if (!terminated) {
                ++failures;

                if (options.tree && pid != target) {
                    std::wcout << L"ERROR: The process with PID " << pid
                               << L" (child process of PID " << target << L") could not be terminated.\n";
                    std::wcout << L"Reason: This process can only be terminated forcefully (with /F option).\n";
                }
                else if (!processInfo) {
                    std::wcout << L"ERROR: The process \"" << pid << L"\" not found.\n";
                }
                else {
                    std::wcout << L"ERROR: The process \"" << imageName << L"\" with PID " << pid
                               << L" could not be terminated.\n";
                }
                continue;
            }

            if (options.tree && pid != target) {
                std::wcout << L"SUCCESS: The process with PID " << pid
                           << L" (child process of PID " << target << L") has been terminated.\n";
                continue;
            }

            if (options.force) {
                std::wcout << L"SUCCESS: The process \"" << imageName << L"\" with PID " << pid
                           << L" has been terminated.\n";
                continue;
            }

            if (!options.imageNames.empty()) {
                std::wcout << L"SUCCESS: Sent termination signal to the process \"" << imageName
                           << L"\" with PID " << pid << L".\n";
            }
            else {
                std::wcout << L"SUCCESS: Sent termination signal to the process with PID " << pid << L".\n";
            }
        }
    }

    return failures == 0 ? 0 : 1;
}

} // namespace

// Wide-character entry point so Unicode process names and credentials work.
int wmain(int argc, wchar_t* argv[]) {
    Options options;
    if (!ParseArgs(argc, argv, options)) {
        std::wcout << L"Type \"TASKKILL /?\" for usage.\n";
        return 1;
    }

    if (options.showHelp) {
        PrintHelp();
        return 0;
    }

    return RunTaskkill(options);
}
