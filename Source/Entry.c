#include <Core.h>
#include <Win32.h>
#include <Structs.h>
#include <HellsHall.h>
#include <Sleep.h>


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
    do
        // Start Sleep Obfuscation by da spider
        Ekko( 1 * 1000 );
    while ( TRUE );
} 

