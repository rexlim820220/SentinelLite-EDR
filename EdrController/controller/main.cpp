#include <windows.h>
#include <iostream>
#include <string>
#include "safe_queue.hpp"
#include "event.hpp"
#include "hook.hpp"

extern std::wstring g_processName;

ThreadSafeQueue  g_queue(1000);
ThreadSafeQueue* g_pSafeQueue = &g_queue;

static void SetColor(Severity sev) {
    HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
    switch (sev) {
    case Severity::Critical:
        ::SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY);
        break;
    case Severity::Warning:
        ::SetConsoleTextAttribute(h,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        break;
    default:
        ::SetConsoleTextAttribute(h,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        break;
    }
}

static void ResetColor() {
    ::SetConsoleTextAttribute(::GetStdHandle(STD_OUTPUT_HANDLE),
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void PrintEvent(const SecurityEvent& ev) {
    const char* prefix = "[INFO    ]";
    if (ev.severity == Severity::Critical) prefix = "[CRITICAL]";
    else if (ev.severity == Severity::Warning)  prefix = "[WARNING ]";

    SetColor(ev.severity);

    std::string nameUtf8 = WstrToUtf8(ev.process_name);
    std::string detailsUtf8 = WstrToUtf8(ev.details);

    printf("%s PID=%-6u API=%-20s Process=%-25s | %s\n",
        prefix,
        ev.process_id,
        ApiTypeToStr(ev.api_called),
        nameUtf8.c_str(),
        detailsUtf8.c_str());

    ResetColor();
}

int main() {
    ::SetConsoleOutputCP(CP_UTF8);

    {
        wchar_t buf[MAX_PATH] = {};
        DWORD len = MAX_PATH;
        if (::QueryFullProcessImageNameW(::GetCurrentProcess(), 0, buf, &len)) {
            std::wstring full(buf);
            size_t pos = full.rfind(L'\\');
            g_processName = (pos != std::wstring::npos)
                ? full.substr(pos + 1) : full;
        }
        else {
            g_processName = L"controller.exe";
        }
    }

    DWORD pid = ::GetCurrentProcessId();

    printf("==================================================\n");
    printf(" SentinelLite-EDR v0.1  (Self-Hook Mode)         \n");
    printf("==================================================\n");
    printf("[*] Controller PID: %lu\n", pid);
    printf("[*] Run injection_demo.exe %lu to trigger alerts\n", pid);
    printf("[*] Press Ctrl+C to stop.\n");
    printf("--------------------------------------------------\n\n");

    InitializeHooks(g_queue);
    printf("[*] Hooks installed: VirtualAllocEx, CreateRemoteThread, RegSetValueExW\n\n");

    LPVOID testAlloc = ::VirtualAllocEx(
        ::GetCurrentProcess(), nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (testAlloc) ::VirtualFreeEx(::GetCurrentProcess(), testAlloc, 0, MEM_RELEASE);

    printf("[*] Simulating Process Injection sequence (self-target)...\n\n");
    ::Sleep(1000);

    // Step 1: VirtualAllocEx 對自己（模擬跨進程，用自己的 handle）
    HANDLE hSelf = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());

    LPVOID pMem = ::VirtualAllocEx(
        hSelf, nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    ::Sleep(500);

    // Step 2: WriteProcessMemory
    BYTE payload[] = { 0x90, 0x90, 0x90, 0xC3 };
    SIZE_T written = 0;
    ::WriteProcessMemory(hSelf, pMem, payload, sizeof(payload), &written);
    ::Sleep(500);

    // Step 3: CreateRemoteThread
    HANDLE hThread = ::CreateRemoteThread(
        hSelf, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pMem),
        nullptr, 0, nullptr
    );
    ::Sleep(500);

    // 清理
    if (hThread) { ::WaitForSingleObject(hThread, 1000); ::CloseHandle(hThread); }
    if (pMem)    ::VirtualFreeEx(hSelf, pMem, 0, MEM_RELEASE);
    ::CloseHandle(hSelf);

    printf("\n[*] Simulation complete. Entering monitor mode...\n\n");

    while (true) {
        SecurityEvent ev;
        bool got = g_queue.Pop(ev, std::chrono::milliseconds(500));
        if (!got) {
            if (g_queue.IsShutdown()) break;
            continue;
        }
        PrintEvent(ev);
    }

    UninitializeHooks();
    g_queue.Shutdown();
    printf("\n[*] Monitor stopped. Hooks removed.\n");
    return 0;
}