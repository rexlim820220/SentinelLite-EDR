// controller/main.cpp
// SentinelLite-EDR — Controller（Self-Hook 模式）
//
// 架構說明：
//   這個 EXE 直接呼叫 InitializeHooks() 把 hook 安裝在自己的 Process 內。
//   不需要 injector，不需要 Named Pipe。
//   suspicious_app.exe 對本 EXE 的 PID 執行注入動作，
//   hook 攔截到後把事件放進 g_queue，主執行緒 Pop 後印出。

#include <windows.h>
#include <iostream>
#include <string>
#include "safe_queue.hpp"
#include "event.hpp"
#include "hook.hpp"

// ── 全域 queue（定義在此，hook.cpp 用 extern 引用）─────────
ThreadSafeQueue  g_queue(1000);
ThreadSafeQueue* g_pSafeQueue = &g_queue;   // api_monitor.cpp extern 這個

// ── Console 顏色輔助 ─────────────────────────────────────────
static void SetColor(Severity sev) {
    HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
    switch (sev) {
        case Severity::Critical:
            ::SetConsoleTextAttribute(h,
                FOREGROUND_RED | FOREGROUND_INTENSITY);
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

// ── 印出單一事件 ─────────────────────────────────────────────
static void PrintEvent(const SecurityEvent& ev) {
    const char* prefix = "[INFO    ]";
    if      (ev.severity == Severity::Critical) prefix = "[CRITICAL]";
    else if (ev.severity == Severity::Warning)  prefix = "[WARNING ]";

    SetColor(ev.severity);

    // process_name / details 是 wstring，轉成 string 印出
    std::string nameUtf8    = WstrToUtf8(ev.process_name);
    std::string detailsUtf8 = WstrToUtf8(ev.details);

    printf("%s PID=%-6u API=%-20s Process=%-25s | %s\n",
        prefix,
        ev.process_id,
        ApiTypeToStr(ev.api_called),
        nameUtf8.c_str(),
        detailsUtf8.c_str());

    ResetColor();
}

// ── main ─────────────────────────────────────────────────────
int main() {
    ::SetConsoleOutputCP(CP_UTF8);

    DWORD pid = ::GetCurrentProcessId();

    printf("==================================================\n");
    printf(" SentinelLite-EDR v0.1  (Self-Hook Mode)         \n");
    printf("==================================================\n");
    printf("[*] Controller PID: %lu\n", pid);
    printf("[*] Run injection_demo.exe %lu to trigger alerts\n", pid);
    printf("[*] Press Ctrl+C to stop.\n");
    printf("--------------------------------------------------\n\n");

    // ── 安裝 Hook（在本 Process 內） ────────────────────────
    InitializeHooks(g_queue);
    printf("[*] Hooks installed: VirtualAllocEx, CreateRemoteThread, RegSetValueExW\n\n");

    // ── 主迴圈：Pop 事件並印出 ──────────────────────────────
    // Pop 有 timeout，不會忙等；Ctrl+C 會觸發 Windows 的
    // CTRL_C_EVENT，這裡用簡單的方式：偵測到 queue shutdown 就退出
    while (true) {
        SecurityEvent ev;
        bool got = g_queue.Pop(ev, std::chrono::milliseconds(500));

        if (!got) {
            // timeout：queue 正常，繼續等
            // 如果 queue 已 shutdown（不應發生在這個路徑），退出
            if (g_queue.IsShutdown()) break;
            continue;
        }

        PrintEvent(ev);
    }

    // ── 清理 ────────────────────────────────────────────────
    UninitializeHooks();
    g_queue.Shutdown();
    printf("\n[*] Monitor stopped. Hooks removed.\n");
    return 0;
}