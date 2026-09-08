/****************************************************************************************************
*                                                                                                   *
*  File:         Auxiliary.h                                                                        *
*  Purpose:      Auxiliary functionality.                                                           *
*                                                                                                   *
*****************************************************************************************************/
#pragma once
#include <Windows.h>
#include <stdio.h>
#include <sal.h>

#ifdef _DEBUG
#define DEBUG_MSG(pwszFmt, ...)      (VOID)wprintf(L"%S: " pwszFmt L"\n", __FUNCTION__, __VA_ARGS__)
#else
#define DEBUG_MSG(pwszFmt, ...)
#endif

#ifdef _DEBUG
#define DEBUG_ASSERT(cond)          do                                                          \
                                    {                                                           \
                                        if (!(cond))                                            \
                                        {                                                       \
                                            DebugBreak();                                       \
                                        }                                                       \
                                    } while (FALSE)
#else
#define DEBUG_ASSERT(cond)
#endif

#define COMPILE_TIME_ASSERT(cond)   enum { DUMMY = 1/(!!(cond)) }

typedef LONG RETSTATUS;

#define RETSTATUS_FAILED(eStatus)                       (0 > (eStatus))
#define RETSTATUS_SUCCEEDED(eStatus)                    (!(RETSTATUS_FAILED(eStatus)))
#define RETSTATUS_UNEXPECTED ((RETSTATUS)(INT_MIN))
#define RETSTATUS_SUCCESS ((RETSTATUS)0)
#define RETSTATUS_FAILURE_MSG(pwszFmt, ...)                -__LINE__; DEBUG_MSG(pwszFmt, __VA_ARGS__)

#define CLOSE_HANDLE(hObject)        do                                                         \
                                     {                                                          \
                                          if (NULL != (hObject))                                \
                                          {                                                     \
                                              (VOID)CloseHandle(hObject);                       \
                                              (hObject) = NULL;                                 \
                                          }                                                     \
                                     } while (FALSE)

#define CLOSE_FILE_HANDLE(hFile)     do                                                         \
                                     {                                                          \
                                          if (INVALID_HANDLE_VALUE != (hFile))                  \
                                          {                                                     \
                                              __pragma(warning(push))                           \
                                              __pragma(warning(disable:6387))                   \
                                              (VOID)CloseHandle(hFile);                         \
                                              __pragma(warning(pop))                            \
                                              (hFile) = INVALID_HANDLE_VALUE;                   \
                                          }                                                     \
                                     } while (FALSE)

#define HEAPFREE(pvMem)              do                                                         \
                                     {                                                          \
                                          if (NULL != (pvMem))                                  \
                                          {                                                     \
                                              (VOID)HeapFree(GetProcessHeap(), 0, (pvMem));     \
                                              (pvMem) = NULL;                                   \
                                          }                                                     \
                                     } while (FALSE)

#define HEAPALLOCZ(cbBytes)          (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cbBytes)))
#define MILLISECONDS_IN_SECOND (1000)
