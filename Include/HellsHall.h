#include <windows.h>

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef uint32_t UINT32_T;              // im boojie



#ifndef HELLHALL_H
#define HELLHALL_H


// STRING HASHING

uint32_t crc32b(const uint8_t* str);
#define HASH(API)	(crc32b((uint8_t*)API))


typedef struct _SysFunc {

    PVOID       pInst;          // address of a 'syscall' instruction in ntdll.dll
    PBYTE       pAddress;       // address of the syscall 
    WORD        wSSN;           // syscall number
    UINT32_T    uHash;          // syscall name hash value

}SysFunc, * PSysFunc;


typedef struct _NTDLL {

    PBYTE                       pNtdll;
    PIMAGE_DOS_HEADER           pImgDos;
    PIMAGE_NT_HEADERS           pImgNtHdrs;
    PIMAGE_EXPORT_DIRECTORY     pImgExpDir;
    PDWORD                      pdwArrayOfFunctions;
    PDWORD                      pdwArrayOfNames;
    PWORD                       pwArrayOfOrdinals;

}NTDLL, *PNTDLL;

// FROM HellsHall.c
BOOL InitilizeSysFunc(IN UINT32_T uSysFuncHash, NTDLL* InitilizeSysFunc, SysFunc* sF);
VOID getSysFuncStruct(OUT PSysFunc psF, SysFunc* sF);

// FROM AsmHell.asm
extern VOID SetConfig(WORD wSystemCall, PVOID pSyscallInst);
extern NTSTATUS HellHall();

#endif // !HELLHALL_H
