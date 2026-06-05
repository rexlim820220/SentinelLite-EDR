#include "pch.h"
#include <windows.h>
#include <thread>
#include <atomic>
#include <cstdio>
#include "hook.hpp"
#include "safe_queue.hpp"
#include "event.hpp"

ThreadSafeQueue* g_pSafeQueue = nullptr;
std::wstring     g_processName;

static std::thread g_loggerThread;
static ThreadSafeQueue g_queue(1000);

static void LoggerThreadProc() {
    HANDLE hConsole = ::GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    ::GetConsoleScreenBufferInfo(hConsole, &csbi);
    const WORD originalAttr = csbi.wAttributes;

    while (true){
        SecurityEvent ev;
        bool got = g_queue.Pop(ev, std::chrono::milliseconds(200));

        if(!got){
            if(g_queue.IsShutdown()) break;
            continue;
        }
        WORD color = originalAttr;
        const char* prefix = "[INFO    ]";

        switch(ev.severity){
            case Severity::Critical:
                color = FOREGROUND_RED | FOREGROUND_INTENSITY;
                prefix = "[CRITICAL]";
                break;
            case Severity::Warning:
                color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                prefix = "[WARNING ]";
                break;
            case Severity::Info:
                color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
                prefix = "[INFO    ]";
                break;
            default:
                break;
        }

        ::SetConsoleTextAttribute(hConsole, color);

        std::string nameUtf8    = WstrToUtf8(ev.process_name);
        std::string detailsUtf8 = WstrToUtf8(ev.details);

        printf("%s PID=%-6u API=%-20s Process=%-20s | %s\n",
            prefix,
            ev.process_id,
            ApiTypeToStr(ev.api_called),
            nameUtf8.c_str(),
            detailsUtf8.c_str());

        ::SetConsoleTextAttribute(hConsole, originalAttr);
    }
    ::SetConsoleTextAttribute(hConsole, originalAttr);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hModule);
        {
            wchar_t buf[MAX_PATH] = {};
            DWORD  len = MAX_PATH;
            if(::QueryFullProcessImageNameW(::GetCurrentProcess(), 0, buf, &len)){
                std::wstring fullPath(buf);
                size_t pos = fullPath.rfind(L'\\');
                g_processName = (pos != std::wstring::npos)
                    ?fullPath.substr(pos+1)
                    :fullPath;
            } else {
                g_processName = L"Unknown";
            }
        }
        g_pSafeQueue = &g_queue;
        g_loggerThread = std::thread(LoggerThreadProc);
        InitializeHooks(g_queue);
        break;
    case DLL_THREAD_DETACH:
        if (lpReserved != nullptr) break;

        UninitializeHooks();

        g_queue.Shutdown();
        if (g_loggerThread.joinable()) {
            g_loggerThread.join();
        }

        g_pSafeQueue = nullptr;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

