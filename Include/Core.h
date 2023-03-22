
#include <windows.h>
#include <Macros.h>
#include <stdio.h>
#include <Structs.h>

UINT_PTR GetRIP(VOID);
LPVOID  KaynCaller();

NTSTATUS NTAPI NtContinue ( IN PCONTEXT ContextRecord, IN BOOLEAN TestAlert);
NTSTATUS WINAPI SystemFunction032( PUNICODE_STRING data, PUNICODE_STRING key);

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