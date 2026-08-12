/****************************************************************************************************
*                                                                                                   *
*  File:         Main.c                                                                             *
*  Purpose:      Hardcoded version of CmdSpoofer for testing against CrowdStrike Custom IOA.        *
*                Fake command line is clean, real command line contains the target payload.         *
*                                                                                                   *
*****************************************************************************************************/
#include "Spoofer.h"

INT
wmain(
	INT nArgs,
	PWSTR* ppwszArgs
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;

	// ======================================================
	// HARDCODED VALUES - Change these as needed
	// ======================================================
	PCWSTR pwszFakeCommandline = L"C:\\Windows\\System32\\cmd.exe /c echo hello";
	PCWSTR pwszRealCommandline = L"C:\\Windows\\System32\\cmd.exe /c wwwww";
	DWORD  dwSleepTimeSeconds  = 4;
	// ======================================================

	// Spawn and spoof
	eStatus = SPOOFER_Spawn(
		pwszFakeCommandline,
		pwszRealCommandline,
		dwSleepTimeSeconds,
		FALSE,          // bHideWindow
		FALSE,          // bHideConsole
		NULL            // phProcess
	);

	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"SPOOFER_Spawn() failed (eStatus=%.8x)", eStatus);
		return (INT)eStatus;
	}

	return 0;
}
