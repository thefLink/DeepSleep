# DeepSleep

A variant of Gargoyle for x64 to hide memory artifacts using ROP only and PIC.          

Huge thanks to [@waldoirc](https://twitter.com/waldoirc) for documenting large parts of this technique on his [blog](https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/)          
This implementation is different in that it does not make use of any APCs and is fully implemented as PIC.

## Description

I have created this to better understand how to evade memory artifacts using a [Gargoyle](https://github.com/JLospinoso/gargoyle) like technique on x64.
The idea is to set up a ROPChain calling VirtualProtect() -> Sleep() -> VirtualProtect() to mark my own page as **N/A** while Sleeping.  

Unlike Gargoyle and other Gargoyle-like implementations, I fully rely on ROP and do not queue any APC.
DeepSleep itself is implemented as fully PIC, which makes it easier to enumerate which memory pages have to be hidden from scanners.

While the thread is active, a MessageBox pops up and DeepSleep's page is marked as executable. While Sleeping, the page is marked as **N/A**.

This effectively bypasses [Moneta](https://github.com/forrest-orr/moneta) at the time of writing if DeepSleep is injected and the executing thread's base address 
does not point to private commited memory. 

I have verified this using the [Earlybird](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)
injection technique to inject DeepSleep.bin into notepad.exe

![Moneta finding DeepSleep while showing msgbox](/Screens/MonetaFound.png?raw=true "Moneta finding DeepSleep while showing msgbox")
![Moneta not finding DeepSleep while showing msgbox](/Screens/MonetaNotFound.png?raw=true "Moneta not finding DeepSleep while showing msgbox")

## Usage
Using Mingw:     
Type ```make``` and a wild DeepSleep.bin appears.     
Alternatively use the precompiled DeepSleep.bin :-)

## Future Work and limitations

### Future Work

I might release a loader for CS or other C2 agents. Similarly to [YouMayPasser](https://github.com/waldo-irc/YouMayPasser), the loader would hook sleep using HW breakpoints
to avoid suspicious modifications of kernel32.dll.       

### Limitations

This was tested on ``` 10.0.19044 N/A Build 19044```

The ROPgadgets I am relying on might not exist in ntdll.dll in other versions of Windows. 
It is probably a good idea to make use of smaller and more generic ROPgadgets and to enumerate the gadgets in more dlls than ntdll.dll.

## Detection

The callstack to a thread in the ```DelayExecution``` state includes unknown/tampered memory regions and additionally includes addresses to VirtualProtect()      
It may be possible to apply that metric to other C2 using a different technique to Sleep.

![Weird Stack](/Screens/WeirdTrace.png?raw=true "Weird Trace")

## Credits

[@waldoirc](https://twitter.com/waldoirc) for documenting large parts the technique [here](https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/)               
[@forrest Orr](https://twitter.com/_forrestorr) [Moneta](https://github.com/forrest-orr/moneta)                
[Josh Lospinoso](https://github.com/JLospinoso/) for the original [Gargoyle technique](https://github.com/JLospinoso/gargoyle)             
