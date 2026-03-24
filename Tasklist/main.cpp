#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <cwctype>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")

namespace {

// The program supports three output layouts that roughly match the built-in
// Windows `tasklist` command.

enum class Mode {
    Basic,
    Verbose,
    Services
};

// Parsed command-line switches. Each field is toggled when a matching
// argument is seen in `wmain`.
struct Options {
    bool showHelp = false;
    bool verbose = false;
    bool services = false;
};

// A single row of process information after all Win32 queries have been
// collected and normalized into strings/numbers that are easy to print.
struct ProcessRow {
    std::wstring imageName;
    DWORD pid = 0;
    DWORD sessionId = 0;
    std::wstring sessionName = L"N/A";
    SIZE_T memoryBytes = 0;
    std::wstring status = L"UNKNOWN";
    std::wstring userName = L"N/A";
    std::wstring cpuTime = L"N/A";
    std::wstring windowTitle = L"N/A";
    std::wstring services;
};

// Windows command-line arguments are case-insensitive, so normalize incoming
// text before comparing it with supported switches.
std::wstring ToUpper(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towupper(c)); });
    return value;
}

// Keep a string within a fixed width. This is used to make the console table
// line up cleanly without dealing with dynamic column widths.
std::wstring Truncate(const std::wstring& value, size_t maxWidth) {
    if (value.size() <= maxWidth) {
        return value;
    }
    return value.substr(0, maxWidth);
}

// Left-align text inside a fixed-width column by trimming long values and
// padding shorter ones with spaces on the right.
std::wstring PadOrTrimLeft(const std::wstring& value, size_t width) {
    const std::wstring trimmed = Truncate(value, width);
    if (trimmed.size() >= width) {
        return trimmed;
    }
    return trimmed + std::wstring(width - trimmed.size(), L' ');
}

// Right-align text inside a fixed-width column by trimming long values and
// padding shorter ones with spaces on the left.
std::wstring PadOrTrimRight(const std::wstring& value, size_t width) {
    const std::wstring trimmed = Truncate(value, width);
    if (trimmed.size() >= width) {
        return trimmed;
    }
    return std::wstring(width - trimmed.size(), L' ') + trimmed;
}

// Convert raw bytes into the same kilobyte-style display used by tasklist.
std::wstring FormatMemoryKb(SIZE_T bytes) {
    std::wstringstream stream;
    stream << (bytes / 1024) << L" K";
    return stream.str();
}

// `GetProcessTimes` returns time values in 100-nanosecond units split across
// two FILETIME values. This helper combines kernel + user CPU time and formats
// the result as `hhh:mm:ss`.
std::wstring FormatCpuTime(const FILETIME& kernel, const FILETIME& user) {
    ULARGE_INTEGER kernelValue{};
    kernelValue.LowPart = kernel.dwLowDateTime;
    kernelValue.HighPart = kernel.dwHighDateTime;

    ULARGE_INTEGER userValue{};
    userValue.LowPart = user.dwLowDateTime;
    userValue.HighPart = user.dwHighDateTime;

    const unsigned long long total100ns = kernelValue.QuadPart + userValue.QuadPart;
    const unsigned long long totalSeconds = total100ns / 10000000ULL;

    const unsigned long long hours = totalSeconds / 3600ULL;
    const unsigned long long minutes = (totalSeconds % 3600ULL) / 60ULL;
    const unsigned long long seconds = totalSeconds % 60ULL;

    std::wstringstream stream;
    stream << std::setw(3) << std::setfill(L'0') << hours
           << L":" << std::setw(2) << minutes
           << L":" << std::setw(2) << seconds;
    return stream.str();
}

// Translate a session ID into a displayable session name. Session 0 is the
// special service session on Windows, so it is handled explicitly.
std::optional<std::wstring> QuerySessionName(DWORD sessionId) {
    if (sessionId == 0) {
        return std::wstring(L"Services");
    }

    // WTS allocates the returned string buffer, so it must be released with
    // `WTSFreeMemory` after copying the contents into a C++ string.
    LPWSTR buffer = nullptr;
    DWORD bytes = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSWinStationName, &buffer, &bytes) || !buffer) {
        return std::nullopt;
    }

    std::wstring result(buffer);
    WTSFreeMemory(buffer);
    return result;
}

// Convert the process token's SID into a readable `DOMAIN\User` name.
// Many protected/system processes deny this query, so the fallback is `N/A`.
std::wstring ResolveUserName(HANDLE processHandle) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(processHandle, TOKEN_QUERY, &token)) {
        return L"N/A";
    }

    // First call asks Windows how much space is required for the token data.
    DWORD tokenInfoLength = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(token);
        return L"N/A";
    }

    // Second call retrieves the token information into a correctly sized
    // buffer owned by a C++ vector.
    std::vector<BYTE> tokenBuffer(tokenInfoLength);
    if (!GetTokenInformation(token, TokenUser, tokenBuffer.data(), tokenInfoLength, &tokenInfoLength)) {
        CloseHandle(token);
        return L"N/A";
    }

    const TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenBuffer.data());

    WCHAR name[256] = {};
    WCHAR domain[256] = {};
    DWORD nameLen = static_cast<DWORD>(std::size(name));
    DWORD domainLen = static_cast<DWORD>(std::size(domain));
    SID_NAME_USE sidType;

    if (!LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
        CloseHandle(token);
        return L"N/A";
    }

    CloseHandle(token);

    if (domain[0] == L'\0') {
        return std::wstring(name);
    }

    return std::wstring(domain) + L"\\" + name;
}

// Small state object passed into `EnumWindows` so the callback knows which
// process ID it is trying to match.
struct WindowSearch {
    DWORD pid;
    std::wstring title;
};

// Callback used by `EnumWindows`. It stops when it finds the first visible
// top-level window owned by the requested process that has a non-empty title.
BOOL CALLBACK EnumWindowForPid(HWND hwnd, LPARAM lParam) {
    WindowSearch* state = reinterpret_cast<WindowSearch*>(lParam);
    DWORD windowPid = 0;
    GetWindowThreadProcessId(hwnd, &windowPid);

    if (windowPid != state->pid || !IsWindowVisible(hwnd)) {
        return TRUE;
    }

    const int titleLen = GetWindowTextLengthW(hwnd);
    if (titleLen <= 0) {
        return TRUE;
    }

    std::wstring title;
    title.resize(static_cast<size_t>(titleLen));
    GetWindowTextW(hwnd, title.data(), titleLen + 1);
    state->title = title;
    return FALSE;
}

// Look up a human-readable window title for verbose mode.
std::wstring QueryWindowTitle(DWORD pid) {
    WindowSearch search{ pid, L"" };
    EnumWindows(EnumWindowForPid, reinterpret_cast<LPARAM>(&search));
    return search.title.empty() ? L"N/A" : search.title;
}

// Build a lookup table from process ID to comma-separated service names.
// This is needed for `/SVC`, and it also helps identify service-hosted
// processes in the normal output modes.
std::map<DWORD, std::wstring> BuildServiceMap() {
    std::map<DWORD, std::vector<std::wstring>> accumulator;

    // Open the Service Control Manager with just enough access to enumerate
    // installed/running services.
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        return {};
    }

    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    DWORD resumeHandle = 0;

    // First call intentionally uses a null buffer so Windows tells us how much
    // memory is needed for the result set.
    EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        nullptr,
        0,
        &bytesNeeded,
        &serviceCount,
        &resumeHandle,
        nullptr);

    if (GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0) {
        CloseServiceHandle(scm);
        return {};
    }

    // Second call uses the correctly sized buffer and fills it with service
    // status records.
    std::vector<BYTE> buffer(bytesNeeded);
    if (!EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytesNeeded,
            &serviceCount,
            &resumeHandle,
            nullptr)) {
        CloseServiceHandle(scm);
        return {};
    }

    // Group service names by owning process ID because one process can host
    // multiple services.
    auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    for (DWORD i = 0; i < serviceCount; ++i) {
        const DWORD pid = entries[i].ServiceStatusProcess.dwProcessId;
        if (pid == 0) {
            continue;
        }
        accumulator[pid].push_back(entries[i].lpServiceName ? entries[i].lpServiceName : L"");
    }

    CloseServiceHandle(scm);

    // Flatten each process's service list into a single printable string.
    std::map<DWORD, std::wstring> result;
    for (const auto& [pid, names] : accumulator) {
        std::wstringstream line;
        for (size_t i = 0; i < names.size(); ++i) {
            if (i > 0) {
                line << L", ";
            }
            line << names[i];
        }
        result[pid] = line.str();
    }

    return result;
}

// Print command-line help similar to the Windows tool.
void PrintHelp() {
    std::wcout << L"TASKLIST [/SVC | /V] [/?]\n\n";
    std::wcout << L"Description:\n";
    std::wcout << L"    Displays a list of currently running processes on the local machine.\n\n";
    std::wcout << L"Parameter List:\n";
    std::wcout << L"   /SVC    Displays services hosted in each process.\n";
    std::wcout << L"   /V      Displays verbose task information.\n";
    std::wcout << L"   /?      Displays this help message.\n\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"    TASKLIST\n";
    std::wcout << L"    TASKLIST /V\n";
    std::wcout << L"    TASKLIST /SVC\n";
}

// Match the built-in tool's invalid-combination error message.
void PrintInvalidSyntax() {
    std::wcout << L"ERROR: Invalid syntax. /V, /M and /SVC options cannot be used together.\n";
    std::wcout << L"Type \"TASKLIST /?\" for usage.\n";
}

// Parse supported switches. The function returns `false` when an unknown
// argument or unsupported combination is found.
bool ParseArgs(int argc, wchar_t* argv[], Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = ToUpper(argv[i]);
        if (arg == L"/?") {
            options.showHelp = true;
        }
        else if (arg == L"/V") {
            options.verbose = true;
        }
        else if (arg == L"/SVC") {
            options.services = true;
        }
        else {
            std::wcout << L"ERROR: Invalid argument: " << argv[i] << L"\n";
            std::wcout << L"Type \"TASKLIST /?\" for usage.\n";
            return false;
        }
    }

    if (options.verbose && options.services) {
        PrintInvalidSyntax();
        return false;
    }

    return true;
}

// Print the fixed header lines for the selected display mode.
void PrintHeader(Mode mode) {
    if (mode == Mode::Basic) {
        std::wcout << L"Image Name                     PID Session Name        Session#    Mem Usage\n";
        std::wcout << L"========================= ======== ================ =========== ============\n";
        return;
    }

    if (mode == Mode::Verbose) {
        std::wcout << L"Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title\n";
        std::wcout << L"========================= ======== ================ =========== ============ =============== ================================================== ============ =======================================================================\n";
        return;
    }

    std::wcout << L"Image Name                     PID Services\n";
    std::wcout << L"========================= ======== ===========================================\n";
}

// Print one process row in the default layout.
void PrintBasicRow(const ProcessRow& row) {
    std::wcout << PadOrTrimLeft(row.imageName, 25) << L" "
               << PadOrTrimRight(std::to_wstring(row.pid), 8) << L" "
               << PadOrTrimLeft(row.sessionName, 16) << L" "
               << PadOrTrimRight(std::to_wstring(row.sessionId), 11) << L" "
               << PadOrTrimRight(FormatMemoryKb(row.memoryBytes), 12)
               << L"\n";
}

// Print one process row with the extra fields used by `/V`.
void PrintVerboseRow(const ProcessRow& row) {
    std::wcout << PadOrTrimLeft(row.imageName, 25) << L" "
               << PadOrTrimRight(std::to_wstring(row.pid), 8) << L" "
               << PadOrTrimLeft(row.sessionName, 16) << L" "
               << PadOrTrimRight(std::to_wstring(row.sessionId), 11) << L" "
               << PadOrTrimRight(FormatMemoryKb(row.memoryBytes), 12) << L" "
               << PadOrTrimLeft(row.status, 15) << L" "
               << PadOrTrimLeft(row.userName, 50) << L" "
               << PadOrTrimRight(row.cpuTime, 12) << L" "
               << PadOrTrimLeft(row.windowTitle, 71)
               << L"\n";
}

// Print one process row for `/SVC`. If the service list is too long for a
// single line, continue it on additional indented lines.
void PrintServicesRow(const ProcessRow& row) {
    constexpr size_t serviceWidth = 43;
    const std::wstring services = row.services.empty() ? L"N/A" : row.services;

    size_t start = 0;
    bool firstLine = true;
    while (start < services.size()) {
        const std::wstring chunk = Truncate(services.substr(start), serviceWidth);
        if (firstLine) {
            std::wcout << PadOrTrimLeft(row.imageName, 25) << L" "
                       << PadOrTrimRight(std::to_wstring(row.pid), 8) << L" "
                       << PadOrTrimLeft(chunk, serviceWidth) << L"\n";
            firstLine = false;
        }
        else {
            std::wcout << std::wstring(25, L' ') << L" "
                       << std::wstring(8, L' ') << L" "
                       << PadOrTrimLeft(chunk, serviceWidth) << L"\n";
        }
        start += chunk.size();
    }
}

// Query all available information for a process snapshot entry and convert it
// into a single `ProcessRow` that is ready to be printed.
ProcessRow BuildRow(const PROCESSENTRY32W& entry, Mode mode, const std::map<DWORD, std::wstring>& serviceMap) {
    ProcessRow row;
    row.imageName = entry.szExeFile;
    row.pid = entry.th32ProcessID;

    // If the PID appears in the service map, Windows is using that process to
    // host one or more services.
    const auto serviceIt = serviceMap.find(row.pid);
    const bool isServiceProcess = serviceIt != serviceMap.end();

    DWORD sessionId = 0;
    if (ProcessIdToSessionId(row.pid, &sessionId)) {
        row.sessionId = sessionId;
        const std::optional<std::wstring> sessionName = QuerySessionName(sessionId);
        if (sessionName.has_value() && !sessionName->empty()) {
            row.sessionName = *sessionName;
        }
    }
    // Some protected processes can fail this query even though they are known
    // service hosts, so fall back to the service map when possible.
    else if (isServiceProcess) {
        row.sessionId = 0;
        row.sessionName = L"Services";
    }

    // Prefer the broader query right first because it allows more APIs to work
    // on older/protected processes. If that fails, try the limited right.
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, row.pid);
    if (!processHandle) {
        processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.pid);
    }

    if (processHandle) {
        // Working set size is the value shown in the tasklist memory column.
        PROCESS_MEMORY_COUNTERS pmc{};
        if (GetProcessMemoryInfo(processHandle, &pmc, sizeof(pmc))) {
            row.memoryBytes = pmc.WorkingSetSize;
        }

        if (mode == Mode::Verbose) {
            // Only gather the extra verbose-only fields when they will actually
            // be printed.
            row.userName = ResolveUserName(processHandle);
            FILETIME createTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime)) {
                row.cpuTime = FormatCpuTime(kernelTime, userTime);
            }
            else {
                row.cpuTime = L"N/A";
            }
        }

        CloseHandle(processHandle);
    }

    if (mode == Mode::Verbose) {
        // A visible titled window is used here as a simple approximation of a
        // process being interactively "running".
        row.windowTitle = QueryWindowTitle(row.pid);
        row.status = row.windowTitle == L"N/A" ? L"UNKNOWN" : L"RUNNING";
    }

    if (mode == Mode::Services && isServiceProcess) {
        row.services = serviceIt->second;
    }

    return row;
}

// Enumerate all processes from a Tool Help snapshot, build a printable row for
// each one, and send the result to the console.
int RunTasklist(Mode mode) {
    // Build the service map once up front so it can be reused for every row.
    const std::map<DWORD, std::wstring> serviceMap = BuildServiceMap();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"ERROR: Could not enumerate processes.\n";
        return 1;
    }

    PrintHeader(mode);

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        std::wcout << L"ERROR: Could not read process list.\n";
        return 1;
    }

    do {
        const ProcessRow row = BuildRow(entry, mode, serviceMap);
        if (mode == Mode::Basic) {
            PrintBasicRow(row);
        }
        else if (mode == Mode::Verbose) {
            PrintVerboseRow(row);
        }
        else {
            PrintServicesRow(row);
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

} // namespace

// Wide-character entry point so Unicode command-line arguments are handled
// correctly on Windows.
int wmain(int argc, wchar_t* argv[]) {
    Options options;
    if (!ParseArgs(argc, argv, options)) {
        return 1;
    }

    // Help short-circuits normal execution.
    if (options.showHelp) {
        PrintHelp();
        return 0;
    }

    // Choose exactly one output mode based on the supplied switches.
    Mode mode = Mode::Basic;
    if (options.verbose) {
        mode = Mode::Verbose;
    }
    else if (options.services) {
        mode = Mode::Services;
    }

    return RunTasklist(mode);
}
