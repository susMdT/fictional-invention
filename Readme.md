# HellHallShellcodeTemplate

Credit to [C5pider](https://github.com/Cracked5pider), [mrd0x](https://github.com/mrd0x), and [NUL0x4C](https://github.com/NUL0x4C) for [their](https://github.com/Cracked5pider/ShellcodeTemplate) [work](https://github.com/Maldev-Academy/HellHall)

I honestly don't know what the fuck I'm cooking. Current things this "project" supports/is capable of  
* Indirect syscalls via HellsHall
* Producing Shellcode (via ShellcodeTemplate), Exes, and Dlls
* Sleep encryption via Ekko. Only works on Exes and Shellcode.

Section Organization: Order matters, sorta, so I'm gonna try to document things out here  
* A    => Start aka the entrypoint  
* B    => KaynCaller; here so less to iterate through  
* C    => General Functions  
* D    => Protect Stub
* E    => GetRIPE; arbitrary function to indicate + calculate size of the Protect stub
* $END => GetRIPEnd; arbitrary function to indicate + calculate end of shellcode