make:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	nasm -f win64 asmStubs.nasm -o asmStubs.o 
	x86_64-w64-mingw32-gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,--no-seh
	x86_64-w64-mingw32-gcc Main.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o Main.o -Wl,--no-seh
	x86_64-w64-mingw32-ld -s adjuststack.o asmStubs.o ApiResolve.o Main.o -o DeepSleep.exe

	objcopy -O binary DeepSleep.exe DeepSleep.bin
