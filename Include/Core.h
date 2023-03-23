
#include <windows.h>
#include <Macros.h>
#include <stdio.h>
#include <Structs.h>

UINT_PTR GetRIP(VOID);
UINT_PTR GetRIPE(VOID);
UINT_PTR GetRIPEnd(VOID);
LPVOID  KaynCaller();
LPVOID Start();
VOID Entry( VOID );
NTSTATUS ProtStub();

// Definitions don't matter, just need to be declared
NTSTATUS NTAPI NtContinue();
NTSTATUS WINAPI SystemFunction032();
NTSTATUS NTAPI NtProtectVirtualMemory();
NTSTATUS NTAPI NtWaitForSingleObject();
typedef struct {

    struct {
        WIN32_FUNC( LoadLibraryA );
        WIN32_FUNC( CreateEventW );
        WIN32_FUNC( CreateTimerQueue );
        WIN32_FUNC( RtlSecureZeroMemory );
        WIN32_FUNC( printf );
        WIN32_FUNC( memcpy );
        WIN32_FUNC( NtContinue );
        WIN32_FUNC( SystemFunction032 );
        WIN32_FUNC( GetModuleHandleA );
        WIN32_FUNC( GetProcAddress );
        WIN32_FUNC( RtlCaptureContext );
        WIN32_FUNC( VirtualProtect );
        WIN32_FUNC( WaitForSingleObject );
        WIN32_FUNC( CreateTimerQueueTimer );
        WIN32_FUNC( SetEvent );
        WIN32_FUNC( DeleteTimerQueue );
        WIN32_FUNC( NtProtectVirtualMemory );
        WIN32_FUNC( NtWaitForSingleObject );
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

typedef struct
{
    SIZE_T StackArgs;   // Indicates to the stub how many of the args to iterate through
    PVOID Args[16];     // up to 16 in size, index 15
} ProtStubArgs, *PProtStubArgs;