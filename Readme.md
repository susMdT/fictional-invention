# idfk

Credit to [C5pider](https://github.com/Cracked5pider), [mrd0x](https://github.com/mrd0x), and [NUL0x4C](https://github.com/NUL0x4C) for [their](https://github.com/Cracked5pider/ShellcodeTemplate) [work](https://github.com/Maldev-Academy/HellHall)

I honestly don't know what the fuck I'm cooking. Current things this "project" supports/is capable of  
* Indirect syscalls via HellsHall. Only did it for the protect call and some other common ones, too lazy for others
* Producing Shellcode (via ShellcodeTemplate), exes, dlls.  
* Sleep encryption via Ekko. Only works on  Shellcode. 
* I managed to injected to explorer/locally and it works, but if theres more than one instance of the shellcode is already there, only one of them will cycle.  

Section Organization: Order matters, sorta, so I'm gonna try to document things out here  
* A    => Start aka the entrypoint  
* B    => KaynCaller; here so less to iterate through. Probably doesnt matter but ehhhh  
* C    => General Functions    
* D    => Protect Stub  
* E    => GetRIPE; arbitrary function to indicate + calculate size of the Protect stub  
* $END => GetRIPEnd; arbitrary function to indicate + calculate end of shellcode  
