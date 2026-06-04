#include "pch.h"
#include "hook.hpp"
#include <windows.h>
#include "Detours/detours.h"

extern void AttachAllHooks();
extern void DetachAllHooks();

void InitializeHooks(ThreadSafeQueue& queue)
{
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
}