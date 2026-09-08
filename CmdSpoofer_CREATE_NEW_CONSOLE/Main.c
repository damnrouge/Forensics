/****************************************************************************************************
*                                                                                                   *
*  File:         Main.c                                                                             *
*  Purpose:      Main function for the commandline spoofer.                                         *
*                                                                                                   *
*****************************************************************************************************/
#include "Spoofer.h"

typedef enum
{
	ARG_INDEX_SELF = 0,
	ARG_INDEX_FAKE_COMMANDLINE,
	ARG_INDEX_REAL_COMMANDLINE,
	ARG_INDEX_SLEEP_TIME_SECONDS,
	ARG_INDEX_MAX
} ARG_INDEX;

__success(return >= 0)
static
RETSTATUS
main_ParseU32(
	__in __notnull PCWSTR pwszString,
	__out __notnull PDWORD pdwValue
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PCWSTR pwszEnd = NULL;
	DWORD dwValue = 0;

	DEBUG_ASSERT(NULL != pwszString);
	DEBUG_ASSERT(NULL != pdwValue);

	dwValue = wcstoul(pwszString, &pwszEnd, 10);
	if ((pwszEnd == pwszString) || (L'\0' !=  *pwszEnd))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Input string is not a valid decimal number");
		goto lblCleanup;
	}

	*pdwValue = dwValue;
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:
	return eStatus;
}

__success(return >= 0)
INT
wmain(
	__in INT nArgs,
	__in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	DWORD dwSleepTimeSeconds = 0;

	if (ARG_INDEX_MAX > nArgs)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Insufficient arguments (nArgs=%d)", nArgs);
		goto lblCleanup;
	}

	eStatus = main_ParseU32(ppwszArgs[ARG_INDEX_SLEEP_TIME_SECONDS], &dwSleepTimeSeconds);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"main_ParseU32() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	/* bHideWindow=FALSE, bHideConsole=FALSE -> CREATE_NEW_CONSOLE */
	eStatus = SPOOFER_Spawn(ppwszArgs[ARG_INDEX_FAKE_COMMANDLINE], ppwszArgs[ARG_INDEX_REAL_COMMANDLINE], dwSleepTimeSeconds, FALSE, FALSE, NULL);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"SPOOFER_Spawn() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	eStatus = RETSTATUS_SUCCESS;

lblCleanup:
	return (INT)eStatus;
}
