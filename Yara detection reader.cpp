#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <chrono>
#include <type_traits>

struct YaraResult {
    int ReaderCount;
    int SCAN_BAD_CERT;
    int SCAN_NEUTRAL;
    int SCAN_SUSPICIOUS;
    int SCAN_LIKELY_MALICIOUS;
    int SCAN_MALICIOUS;
};

static_assert(sizeof(YaraResult) == 24, "YaraResult size mismatch");

class HandleGuard {
public:
    HandleGuard(HANDLE h) noexcept : handle(h) {}
    ~HandleGuard() noexcept { if (handle != INVALID_HANDLE_VALUE && handle) CloseHandle(handle); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    operator HANDLE() const noexcept { return handle; }
private:
    HANDLE handle;
};

namespace Console {
    inline void MoveCursorToTop() noexcept {
        SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), {0, 0});
    }

    [[noreturn]] inline void Fail(const char* msg) {
        std::cerr << msg << '\n';
        ExitProcess(1);
    }

    void Configure() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) Fail("Failed to get console handle");

        if (!SetConsoleScreenBufferSize(hConsole, {30, 5})) Fail("Failed to set buffer size");

        SMALL_RECT windowSize = {0, 0, 29, 4};
        if (!SetConsoleWindowInfo(hConsole, TRUE, &windowSize)) Fail("Failed to set window size");

        HWND hwnd = GetConsoleWindow();
        if (!hwnd || !SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)) {
            Fail("Failed to set window topmost");
        }

        CONSOLE_CURSOR_INFO cursorInfo = {1, FALSE};
        if (!SetConsoleCursorInfo(hConsole, &cursorInfo)) Fail("Failed to hide cursor");

        if (!SetConsoleTitleA("Yara Detection Reader - Modified by lithium - e1da58b32b1c4d64")) {
            Fail("Failed to set title");
        }
    }

    void Print(const YaraResult& results) noexcept {
        MoveCursorToTop();
        std::cout << std::left << std::setw(30) << ("SCAN_BAD_CERT = " + std::to_string(results.SCAN_BAD_CERT)) << '\n'
                  << std::left << std::setw(30) << ("SCAN_NEUTRAL = " + std::to_string(results.SCAN_NEUTRAL)) << '\n'
                  << std::left << std::setw(30) << ("SCAN_SUSPICIOUS = " + std::to_string(results.SCAN_SUSPICIOUS)) << '\n'
                  << std::left << std::setw(30) << ("SCAN_LIKELY_MALICIOUS = " + std::to_string(results.SCAN_LIKELY_MALICIOUS)) << '\n'
                  << std::left << std::setw(30) << ("SCAN_MALICIOUS = " + std::to_string(results.SCAN_MALICIOUS)) << std::endl;
    }
}

DWORD GetPID(const char* processName) noexcept {
    DWORD pids[1024], cbNeeded;
    if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) return 0;
    for (unsigned int i = 0; i < cbNeeded / sizeof(DWORD); ++i) {
        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]));
        if (!hProcess) continue;
        char name[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, name, &size)) {
            if (_stricmp(strrchr(name, '\\') + 1, processName) == 0) return pids[i];
        }
    }
    return 0;
}

uintptr_t GetModuleBaseAddress(DWORD pid, const char* moduleName) noexcept {
    HandleGuard hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me32 = {sizeof(me32)};
    if (!Module32First(hSnapshot, &me32)) return 0;
    do {
        if (_stricmp(me32.szModule, moduleName) == 0) return (uintptr_t)me32.modBaseAddr;
    } while (Module32Next(hSnapshot, &me32));
    return 0;
}

int main() {
    Console::Configure();

    DWORD pid = GetPID("RobloxPlayerBeta.exe");
    if (!pid) Console::Fail("Roblox process not found");

    HandleGuard pHandle(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!pHandle) Console::Fail("Failed to open process");

    uintptr_t hyperionBase = GetModuleBaseAddress(pid, "RobloxPlayerBeta.dll");
    if (!hyperionBase) Console::Fail("Failed to find module");

    constexpr uintptr_t YARA_RESULT_OFFSET = 0x2D7540;
    const uintptr_t yaraResultAddress = hyperionBase + YARA_RESULT_OFFSET;

    auto lastCheck = std::chrono::steady_clock::now();
    YaraResult results;
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastCheck).count() >= 1000) {
            lastCheck = now;
            DWORD exitCode;
            if (!GetExitCodeProcess(pHandle, &exitCode) || exitCode != STILL_ACTIVE) {
                Console::Fail("Roblox process terminated");
            }
        }

        if (!ReadProcessMemory(pHandle, (LPCVOID)yaraResultAddress, &results, sizeof(YaraResult), nullptr)) {
            Console::Fail("Failed to read memory");
        }

        Console::Print(results);
        Sleep(100);
    }
}
