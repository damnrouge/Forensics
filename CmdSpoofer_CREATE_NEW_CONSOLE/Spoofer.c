/****************************************************************************************************
*                                                                                                   *
*  File:         Spoofer.c                                                                          *
*  Purpose:      Spoofs a new child process commandline.                                            *
*                                                                                                   *
*****************************************************************************************************/
#include "Spoofer.h"
#include <string.h>
#include <winternl.h>
#include <winnt.h>

#define MAX_COMMANDLINE_CHARS (32767)

__success(return >= 0)
typedef
NTSTATUS(NTAPI* PFN_NTQUERYINFORMATIONPROCESS)(
	__in __notnull HANDLE hProcess,
	__in PROCESSINFOCLASS eProcessInformationClass,
	__out_bcount(cbProcessInformation) __notnull PVOID pvProcessInformation,
	__in ULONG cbProcessInformation,
	__out_opt PULONG pcbReturnLength
);

__success(return >= 0)
static
RETSTATUS
spoofer_CreateDebuggedChild(
	__in __notnull PCWSTR pwszCommandline,
	__in BOOL bHideWindow,
	__in BOOL bHideConsole,
	__out __notnull PHANDLE phProcess,
	__out __notnull PHANDLE phThread
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	STARTUPINFOW tStartupInfo = { 0 };
	PROCESS_INFORMATION tProcInfo = { 0 };
	DWORD dwCreationFlags = 0;
	PWSTR pwszDuplicatedCommandline = NULL;
	SIZE_T cchCommandlineLength = 0;
	SIZE_T cbCommandlineLength = 0;

	DEBUG_ASSERT(NULL != pwszCommandline);
	DEBUG_ASSERT(NULL != phProcess);
	DEBUG_ASSERT(NULL != phThread);

	tStartupInfo.cb = sizeof(tStartupInfo);
	if (bHideWindow)
	{
		tStartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
		tStartupInfo.wShowWindow = SW_HIDE;
	}

	/* DEBUG_ONLY_THIS_PROCESS required to wait for kernel32 before PEB patch.
	   CREATE_NEW_CONSOLE and CREATE_NO_WINDOW are mutually exclusive. */
	dwCreationFlags = DEBUG_ONLY_THIS_PROCESS;
	if (bHideConsole)
	{
		dwCreationFlags |= CREATE_NO_WINDOW;
	}
	else
	{
		dwCreationFlags |= CREATE_NEW_CONSOLE;
	}

	cchCommandlineLength = wcslen(pwszCommandline);
	cbCommandlineLength = (cchCommandlineLength + 1) * sizeof(*pwszCommandline);
	pwszDuplicatedCommandline = HEAPALLOCZ(cbCommandlineLength);
	if (NULL == pwszDuplicatedCommandline)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Commandline allocation failed (cbCommandlineLength=%Iu)", cbCommandlineLength);
		goto lblCleanup;
	}
	CopyMemory(pwszDuplicatedCommandline, pwszCommandline, cbCommandlineLength);

	if (!CreateProcessW(NULL, pwszDuplicatedCommandline, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &tStartupInfo, &tProcInfo))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"CreateProcessW() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	*phProcess = tProcInfo.hProcess;
	tProcInfo.hProcess = NULL;
	*phThread = tProcInfo.hThread;
	tProcInfo.hThread = NULL;
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:
	CLOSE_HANDLE(tProcInfo.hProcess);
	CLOSE_HANDLE(tProcInfo.hThread);
	HEAPFREE(pwszDuplicatedCommandline);
	return eStatus;
}

__success(return >= 0)
static
RETSTATUS
spoofer_DrainDebugEvents(
	__in __notnull HANDLE hThread,
	__in __notnull DEBUG_EVENT* ptDebugEvent
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	DEBUG_EVENT tDebugEvent = { 0 };

	DEBUG_ASSERT(NULL != hThread);
	DEBUG_ASSERT(NULL != ptDebugEvent);

	if ((DWORD)-1 == SuspendThread(hThread))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"SuspendThread() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	if (!ContinueDebugEvent(ptDebugEvent->dwProcessId, ptDebugEvent->dwThreadId, DBG_CONTINUE))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"ContinueDebugEvent() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	while (WaitForDebugEvent(&tDebugEvent, 0))
	{
		switch (tDebugEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			CLOSE_FILE_HANDLE(tDebugEvent.u.CreateProcessInfo.hFile);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			CLOSE_FILE_HANDLE(tDebugEvent.u.LoadDll.hFile);
			break;
		}

		if (!ContinueDebugEvent(tDebugEvent.dwProcessId, tDebugEvent.dwThreadId, DBG_CONTINUE))
		{
			eStatus = RETSTATUS_FAILURE_MSG(L"ContinueDebugEvent() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}
	}

	if (!DebugActiveProcessStop(ptDebugEvent->dwProcessId))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"DebugActiveProcessStop() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	if ((DWORD)-1 == ResumeThread(hThread))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"ResumeThread() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	eStatus = RETSTATUS_SUCCESS;
lblCleanup:
	return eStatus;
}

__success(return >= 0)
static
RETSTATUS
spoofer_WaitForKernel32(
	__out __notnull DEBUG_EVENT* ptDebugEvent
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	HMODULE hKernel32 = NULL;
	BOOL bFoundKernel32 = FALSE;

	DEBUG_ASSERT(NULL != ptDebugEvent);

	hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (NULL == hKernel32)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"GetModuleHandleW() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	for (;;)
	{
		if (!WaitForDebugEvent(ptDebugEvent, INFINITE))
		{
			eStatus = RETSTATUS_FAILURE_MSG(L"WaitForDebugEvent() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}

		switch (ptDebugEvent->dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			CLOSE_FILE_HANDLE(ptDebugEvent->u.CreateProcessInfo.hFile);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			bFoundKernel32 = (PVOID)hKernel32 == ptDebugEvent->u.LoadDll.lpBaseOfDll;
			CLOSE_FILE_HANDLE(ptDebugEvent->u.LoadDll.hFile);
			break;
		}

		if (bFoundKernel32)
		{
			break;
		}

		if (!ContinueDebugEvent(ptDebugEvent->dwProcessId, ptDebugEvent->dwThreadId, DBG_CONTINUE))
		{
			eStatus = RETSTATUS_FAILURE_MSG(L"ContinueDebugEvent() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}
	}

	eStatus = RETSTATUS_SUCCESS;
lblCleanup:
	return eStatus;
}

__success(return >= 0)
static
RETSTATUS
spoofer_ReadProcMemory(
	__in __notnull HANDLE hProcess,
	__in __notnull PVOID pvAddr,
	__in SIZE_T cbSize,
	__out_bcount(cbSize) __notnull PVOID pvBuffer
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PBYTE pcAddr = (PBYTE)pvAddr;
	PBYTE pcBuffer = (PBYTE)pvBuffer;
	SIZE_T cbOffset = 0;
	SIZE_T cbBytesRead = 0;

	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pvAddr);
	DEBUG_ASSERT(NULL != pvBuffer);

	while (cbOffset < cbSize)
	{
		if (!ReadProcessMemory(hProcess, pcAddr + cbOffset, pcBuffer + cbOffset, cbSize - cbOffset, &cbBytesRead))
		{
			DEBUG_MSG(L"ReadProcessMemory() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}
		cbOffset += cbBytesRead;
	}

	eStatus = RETSTATUS_SUCCESS;
lblCleanup:
	return eStatus;
}

__success(return >= 0)
static
RETSTATUS
spoofer_WriteProcMemory(
	__in __notnull HANDLE hProcess,
	__in __notnull PVOID pvAddr,
	__in SIZE_T cbSize,
	__in_bcount(cbSize) __notnull PVOID pvBuffer
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PBYTE pcAddr = (PBYTE)pvAddr;
	PBYTE pcBuffer = (PBYTE)pvBuffer;
	SIZE_T cbOffset = 0;
	SIZE_T cbBytesWritten = 0;

	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pvAddr);
	DEBUG_ASSERT(NULL != pvBuffer);

	while (cbOffset < cbSize)
	{
		if (!WriteProcessMemory(hProcess, pcAddr + cbOffset, pcBuffer + cbOffset, cbSize - cbOffset, &cbBytesWritten))
		{
			DEBUG_MSG(L"WriteProcessMemory() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}
		cbOffset += cbBytesWritten;
	}

	eStatus = RETSTATUS_SUCCESS;
lblCleanup:
	return eStatus;
}

__success(return >= 0)
static
RETSTATUS
spoofer_ZeroProcMemory(
	__in __notnull HANDLE hProcess,
	__in __notnull PVOID pvAddr,
	__in SIZE_T cbSize
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PBYTE pcZeros = NULL;

	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pvAddr);

	pcZeros = HEAPALLOCZ(cbSize);
	if (NULL == pcZeros)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Zeros buffer allocation failed (cbSize=%Iu)", cbSize);
		goto lblCleanup;
	}

	eStatus = spoofer_WriteProcMemory(hProcess, pvAddr, cbSize, pcZeros);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WriteProcMemory() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	eStatus = RETSTATUS_SUCCESS;
lblCleanup:
	HEAPFREE(pcZeros);
	return eStatus;
}

__success(return >= 0)
static
RETSTATUS
spoofer_SpoofCommandline(
	__in __notnull HANDLE hProcess,
	__in __notnull PCWSTR pwszNewCommandline
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	HMODULE hNtdll = NULL;
	PFN_NTQUERYINFORMATIONPROCESS pfnNtQueryInformationProcess = NULL;
	NTSTATUS eNtStatus = STATUS_INVALID_PARAMETER;
	PROCESS_BASIC_INFORMATION tProcInfo = { 0 };
	PEB tPeb = { 0 };
	RTL_USER_PROCESS_PARAMETERS tProcParams = { 0 };
	SIZE_T cchNewCommandline = 0;
	SIZE_T cbNewCommandline = 0;
	PVOID pvRemoteAllocatedAddress = NULL;
	PBYTE pcUnicodeStringRemoteAddress = NULL;

	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pwszNewCommandline);

	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (NULL == hNtdll)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"GetModuleHandleW() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}
	pfnNtQueryInformationProcess = (PFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (NULL == pfnNtQueryInformationProcess)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"GetProcAddress() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	eNtStatus = pfnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &tProcInfo, sizeof(tProcInfo), NULL);
	if (!NT_SUCCESS(eNtStatus))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"NtQueryInformationProcess() failed (eNtStatus=%.8x)", eNtStatus);
		goto lblCleanup;
	}

	__pragma(warning(suppress: 6387))
	eStatus = spoofer_ReadProcMemory(hProcess, tProcInfo.PebBaseAddress, sizeof(tPeb), &tPeb);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_ReadProcMemory() failed for remote PEB (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	eStatus = spoofer_ReadProcMemory(hProcess, tPeb.ProcessParameters, sizeof(tProcParams), &tProcParams);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_ReadProcMemory() failed for remote process parameters (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	eStatus = spoofer_ZeroProcMemory(hProcess, tProcParams.CommandLine.Buffer, tProcParams.CommandLine.MaximumLength);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_ZeroProcMemory() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	cchNewCommandline = wcslen(pwszNewCommandline);
	cbNewCommandline = (cchNewCommandline + 1) * sizeof(*pwszNewCommandline);
	pvRemoteAllocatedAddress = VirtualAllocEx(hProcess, NULL, cbNewCommandline, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pvRemoteAllocatedAddress)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"VirtualAllocEx() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	eStatus = spoofer_WriteProcMemory(hProcess, pvRemoteAllocatedAddress, cbNewCommandline, (PVOID)pwszNewCommandline);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WriteProcMemory() failed for new commandline buffer (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	tProcParams.CommandLine.Length = (USHORT)(cbNewCommandline - sizeof(*pwszNewCommandline));
	tProcParams.CommandLine.MaximumLength = (USHORT)cbNewCommandline;
	tProcParams.CommandLine.Buffer = pvRemoteAllocatedAddress;
	pcUnicodeStringRemoteAddress = (PBYTE)tPeb.ProcessParameters + FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine);
	eStatus = spoofer_WriteProcMemory(hProcess, pcUnicodeStringRemoteAddress, sizeof(tProcParams.CommandLine), &(tProcParams.CommandLine));
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WriteProcMemory() failed for the new commandline string (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	eStatus = RETSTATUS_SUCCESS;
lblCleanup:
	return eStatus;
}

__success(return >= 0)
RETSTATUS
SPOOFER_Spawn(
	__in __notnull PCWSTR pwszFakeCommandline,
	__in __notnull PCWSTR pwszRealCommandline,
	__in DWORD dwSleepTimeSeconds,
	__in BOOL bHideWindow,
	__in BOOL bHideConsole,
	__out_opt PHANDLE phProcess
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	SIZE_T cchFakeCommandline = 0;
	SIZE_T cchRealCommandline = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	BOOL bTerminateProcess = FALSE;
	DEBUG_EVENT tDebugEvent = { 0 };

	if ((NULL == pwszFakeCommandline) || (NULL == pwszRealCommandline))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Invalid argument(s) (pwszFakeCommandline=%p, pwszRealCommandline=%p)", pwszFakeCommandline, pwszRealCommandline);
		goto lblCleanup;
	}

	cchFakeCommandline = wcslen(pwszFakeCommandline);
	if (MAX_COMMANDLINE_CHARS < cchFakeCommandline)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Fake commandline is too long (cchFakeCommandline=%Iu)", cchFakeCommandline);
		goto lblCleanup;
	}
	cchRealCommandline = wcslen(pwszRealCommandline);
	if (MAX_COMMANDLINE_CHARS < cchRealCommandline)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Real commandline is too long (cchRealCommandline=%Iu)", cchRealCommandline);
		goto lblCleanup;
	}

	eStatus = spoofer_CreateDebuggedChild(pwszFakeCommandline, bHideWindow, bHideConsole, &hProcess, &hThread);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_CreateDebuggedChild() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}
	bTerminateProcess = TRUE;

	Sleep(dwSleepTimeSeconds * MILLISECONDS_IN_SECOND);

	eStatus = spoofer_WaitForKernel32(&tDebugEvent);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WaitForKernel32() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	eStatus = spoofer_SpoofCommandline(hProcess, pwszRealCommandline);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_SpoofCommandline() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	eStatus = spoofer_DrainDebugEvents(hThread, &tDebugEvent);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_DrainDebugEvents() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	bTerminateProcess = FALSE;
	if (NULL != phProcess)
	{
		*phProcess = hProcess;
		hProcess = NULL;
	}
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:
	if (bTerminateProcess)
	{
		(VOID)TerminateProcess(hProcess, 0);
	}
	CLOSE_HANDLE(hProcess);
	CLOSE_HANDLE(hThread);
	return eStatus;
}
