#include "pch.h"
#include "hook.hpp"
#include <windows.h>
#include "Detours/detours.h"

extern void AttachAllHooks();
extern void DetachAllHooks();
ThreadSafeQueue* g_pSafeQueue = nullptr;

void InitializeHooks(ThreadSafeQueue& queue)
{
	g_pSafeQueue = &queue;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	AttachAllHooks();
	DetourTransactionCommit();
}

void UninitializeHooks() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetachAllHooks();
	DetourTransactionCommit();
	g_pSafeQueue = nullptr;
}