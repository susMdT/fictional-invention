
#include <windows.h>
#include <Macros.h>
#include <stdio.h>
#include <Structs.h>

UINT_PTR GetRIP(VOID);
UINT_PTR GetRIPE(VOID);
UINT_PTR GetRIPEnd(VOID);
UINT_PTR GetRSP(VOID);
LPVOID  KaynCaller();
LPVOID Start();
VOID Entry( VOID );
NTSTATUS ProtStub();

// Definitions don't matter, just need to be declared
NTSTATUS NTAPI NtContinue();
NTSTATUS WINAPI SystemFunction032();
NTSTATUS NTAPI NtProtectVirtualMemory();
NTSTATUS NTAPI NtWaitForSingleObject();
NTSTATUS NTAPI NtSetEvent();
NTSTATUS NTAPI NtCreateEvent();
NTSTATUS NTAPI RtlCreateTimerQueue();
NTSTATUS NTAPI RtlCreateTimer();
NTSTATUS NTAPI RtlDeleteTimerQueueEx();
NTSTATUS NTAPI NtSignalAndWaitForSingleObject();
NTSTATUS NTAPI NtSetContextThread();
NTSTATUS NTAPI NtDuplicateObject();
NTSTATUS NTAPI NtGetContextThread();
NTSTATUS NTAPI RtlCopyMappedMemory();
NTSTATUS NTAPI NtAlertThread();
NTSTATUS NTAPI NtDelayExecution();
typedef struct {

    struct {
        WIN32_FUNC( LoadLibraryA );
        WIN32_FUNC( NtCreateEvent );
        WIN32_FUNC( RtlCreateTimerQueue );
        WIN32_FUNC( RtlSecureZeroMemory );
        WIN32_FUNC( printf );
        WIN32_FUNC( NtContinue );
        WIN32_FUNC( SystemFunction032 );
        WIN32_FUNC( GetProcAddress );
        WIN32_FUNC( RtlCaptureContext );
        WIN32_FUNC( RtlCreateTimer );
        WIN32_FUNC( NtSetEvent );
        WIN32_FUNC( RtlDeleteTimerQueueEx );
        WIN32_FUNC( NtProtectVirtualMemory );
        WIN32_FUNC( NtWaitForSingleObject );
        WIN32_FUNC( NtSignalAndWaitForSingleObject );
        WIN32_FUNC( NtSetContextThread );
        WIN32_FUNC( NtDuplicateObject );
        WIN32_FUNC( NtGetContextThread );
        WIN32_FUNC( RtlCopyMappedMemory );
        WIN32_FUNC( NtAlertThread );
        WIN32_FUNC( NtDelayExecution );
    } Win32;

    struct {
        // Basics
        HMODULE     Kernel32;
        HMODULE     Ntdll;
        HMODULE     Msvcrt;
        HMODULE     User32;
        HMODULE     Advapi32;
        HMODULE     Cryptsp;
    } Modules;

} INSTANCE, *PINSTANCE;
extern INSTANCE InstancePlaceholder;

typedef struct
{
    SIZE_T StackArgs;   // Indicates to the stub how many of the args to iterate through
    PVOID Args[16];     // up to 16 in size, index 15
} ProtStubArgs, *PProtStubArgs;