#include "pch.h"
#include "event.hpp"
#include "safe_queue.hpp"
#include <windows.h>
#include "Detours/detours.h"
#include <libloaderapi.h>

extern ThreadSafeQueue* g_pSafeQueue;

using PfnVirtualAllocEx = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
using PfnCreateRemoteThread = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using PfnRegSetValueExW = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);

PfnVirtualAllocEx TrueVirtualAllocEx = ::VirtualAllocEx;
PfnCreateRemoteThread TrueCreateRemoteThread = ::CreateRemoteThread;
PfnRegSetValueExW TrueRegSetValueExW = ::RegSetValueExW;

std::wstring GetCurrentProcessName() {
	wchar_t buffer[MAX_PATH] = { 0 };
	DWORD size = MAX_PATH;
	HANDLE hProcess = ::GetCurrentProcess();
	if (::QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
		std::wstring path(buffer);
		size_t pos = path.find_last_of(L"\\");
		if (pos != std::wstring::npos) {
			return path.substr(pos + 1);
		}
		return path;
	}
	return L"Unknown";
}

LPVOID WINAPI HookedVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAdress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
) {
	SecurityEvent ev;
	ev.process_id = ::GetCurrentProcessId();
	ev.process_name = ::GetCurrentProcessName();
	ev.api_called = ::ApiType::VirtualAllocEx;

	if (hProcess != ::GetCurrentProcess()) {
		ev.severity = Severity::Critical;
		DWORD targetPid = ::GetProcessId(hProcess);

		wchar_t detailsBuf[256];
		wsprintfW(detailsBuf, L"RemotePID=%lu, Size=%llu, Protect=0x%lX", targetPid, (unsigned long long)dwSize, flProtect);
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
	ev.process_name = ::GetCurrentProcessName();
	ev.api_called = ApiType::VirtualAllocEx;

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
	SecurityEvent ev;
	ev.process_id = ::GetCurrentProcessId();
	ev.process_name = ::GetCurrentProcessName();
	ev.api_called = ApiType::RegSetValueEx;
	ev.severity = Severity::Info;
	ev.details = L"Registry write";

	if (lpValueName) {
		ev.details = L"ValueName = " + std::wstring(lpValueName);
		if (wcsstr(lpValueName, L"Run") != nullptr || wcsstr(lpValueName, L"Sentinel") != nullptr)
		{
			ev.severity = Severity::Warning;
			ev.details += L" [POTENTIAL PERSISTENCE]";
		}
	}

	if (g_pSafeQueue) {
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