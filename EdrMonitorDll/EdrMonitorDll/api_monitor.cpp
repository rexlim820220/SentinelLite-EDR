#include "pch.h"
#include "event.hpp"
#include "safe_queue.hpp"
#include <windows.h>
#include "Detours/detours.h"
#include <libloaderapi.h>

using PfnVirtualAllocEx = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
using PfnCreateRemoteThread = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using PfnRegSetValueExW = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);

std::wstring g_processName;

extern ThreadSafeQueue* g_pSafeQueue;
PfnVirtualAllocEx TrueVirtualAllocEx = ::VirtualAllocEx;
PfnCreateRemoteThread TrueCreateRemoteThread = ::CreateRemoteThread;
PfnRegSetValueExW TrueRegSetValueExW = ::RegSetValueExW;

LPVOID WINAPI HookedVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAdress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
) {
	SecurityEvent ev;
	ev.process_id = ::GetCurrentProcessId();
	ev.process_name = g_processName;
	ev.api_called = ::ApiType::VirtualAllocEx;

	if (hProcess != ::GetCurrentProcess()) {
		ev.severity = Severity::Critical;
		DWORD targetPid = ::GetProcessId(hProcess);

		wchar_t detailsBuf[256];
		wsprintfW(detailsBuf, L"RemotePID=%lu, Size=%Iu, Protect=0x%lX", targetPid, (unsigned long long)dwSize, flProtect);
		ev.details = detailsBuf;
	}
	else {
		ev.severity = Severity::Info;
		ev.details = L"Local allocation";
	}

	if (g_pSafeQueue) {
		g_pSafeQueue->Push(std::move(ev));
	}
	return TrueVirtualAllocEx(hProcess, lpAdress, dwSize, flAllocationType, flProtect);
}

HANDLE WINAPI HookedCreateRemoteThread(
	HANDLE hProcess,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
	SecurityEvent ev;
	ev.process_id = ::GetCurrentProcessId();
	ev.process_name = g_processName;
	ev.api_called = ApiType::CreateRemoteThread;

	if (hProcess != ::GetCurrentProcess()) {
		ev.severity = Severity::Critical;
		DWORD targetPid = ::GetProcessId(hProcess);

		wchar_t detailsBuf[256];
		wsprintfW(detailsBuf, L"RemotePID=%lu, StartAddr=0x%p", targetPid, lpStartAddress);
		ev.details = detailsBuf;
	}
	else {
		ev.severity = Severity::Info;
		ev.details = L"Local thread creation";
	}
	if (g_pSafeQueue) {
		g_pSafeQueue->Push(std::move(ev));
	}
	return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
	/**fix: Removed incorrect persistence detection based on lpValueName string matching and replaced it with generic Registry write monitoring that logs ValueName
	 KeyHandle, type, and size, since the actual Registry path is associated with hKey rather than lpValueName. */
	SecurityEvent ev;
    ev.process_id   = ::GetCurrentProcessId();
    ev.process_name = g_processName;
    ev.api_called = ApiType::RegSetValueEx;
    ev.severity = Severity::Warning;

    wchar_t detailsBuf[512] = {};

    wsprintfW(
        detailsBuf,
        L"ValueName=%s, KeyHandle=0x%p, Type=%u, Size=%u",
        lpValueName ? lpValueName : L"(null)",
        hKey,
        dwType,
        cbData);

    ev.details = detailsBuf;

    if (g_pSafeQueue)
    {
        g_pSafeQueue->Push(std::move(ev));
    }

    return TrueRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

void AttachAllHooks() {
	DetourAttach(&(PVOID&)TrueVirtualAllocEx, HookedVirtualAllocEx);
	DetourAttach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);
	DetourAttach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
}

void DetachAllHooks() {
	DetourDetach(&(PVOID&)TrueVirtualAllocEx, HookedVirtualAllocEx);
	DetourDetach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);
	DetourDetach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
}