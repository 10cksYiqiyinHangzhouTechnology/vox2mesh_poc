# vox2mesh_poc

[Project address](https://github.com/cedricpinson/vox2mesh)


# Vulnerability information

vox2mesh project has stack-overflow in main.cpp, this is stack-overflow caused by incorrect use of memcpy() funciton. The flow allows an attacker to cause a denial of service (abort) via a crafted file.

# OS information

```bash
ubuntu@ubuntu:~/Desktop/vox2mesh/build/vox2obj$ uname -a
Linux ubuntu 5.15.0-58-generic #64~20.04.1-Ubuntu SMP Fri Jan 6 16:42:31 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

# Usages original project

```
vox2obj input.vox output.obj
```

# Build instructions

```
mkdir build; cd build;
cmake ../
make
```

# Build afl harness

1. change main() function in main.cpp 

```bash
int main(int argc, char** argv)
{

    Options options;
    int optionIndex = parseArgument(options, argc, argv);
    int numArgs = argc - optionIndex;

    options.inputFile = argv[optionIndex];
    options.outputFile = "output.obj";

    VoxReader reader;
    if (!reader.readFile(options.inputFile)) {
        printf("error reading voxels\n");
        return 1;
    }
```

2. change CMakelist.txt, add code:

```c
set (CMAKE_C_COMPILER "/usr/local/bin/afl-clang-fast")
set (CMAKE_CXX_COMPILER "/usr/local/bin/afl-clang-fast++")
```

# Harness Usages

```
vox2obj input.vox
```

# Build ASAN

change CMakelist.txt, add code:

```c
set(CMAKE_CXX_FLAGS "-fsanitize=address -O1 -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS "-Wall -Werror -Wstrict-prototypes -Wmissing-prototypes")
```

# ASAN

```bash
ubuntu@ubuntu:~/Desktop/vox2mesh/build/vox2obj$ ./vox2obj out/default/crashes/id\:000000\,sig\:11\,src\:000002\,time\:9972\,execs\:836\,op\:havoc\,rep\:4 
Version: 150
ChunkId: MAIN
399 voxels
AddressSanitizer:DEADLYSIGNAL
=================================================================
==38193==ERROR: AddressSanitizer: stack-overflow on address 0x7ffff6f8ccf8 (pc 0x0000004db3b1 bp 0x7fffffffd990 sp 0x7ffff6f8cd00 T0)
    #0 0x4db3b1 in VoxReader::readChunk(unsigned char const*, unsigned int) /home/ubuntu/Desktop/vox2mesh/VoxReader.cpp:138:13
    #1 0x4db541 in VoxReader::readChunk(unsigned char const*, unsigned int) /home/ubuntu/Desktop/vox2mesh/VoxReader.cpp:152:13
    #2 0x4dbb4c in VoxReader::loadVoxelsData(unsigned char const*, unsigned long) /home/ubuntu/Desktop/vox2mesh/VoxReader.cpp:205:9
    #3 0x4cf517 in VoxReader::readFile(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) /home/ubuntu/Desktop/vox2mesh/VoxReader.cpp:186:12
    #4 0x4e66cb in main /home/ubuntu/Desktop/vox2mesh/main.cpp:59:17
    #5 0x7ffff7a5b082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #6 0x4204fd in _start (/home/ubuntu/Desktop/vox2mesh/build/vox2obj/vox2obj+0x4204fd)

SUMMARY: AddressSanitizer: stack-overflow /home/ubuntu/Desktop/vox2mesh/VoxReader.cpp:138:13 in VoxReader::readChunk(unsigned char const*, unsigned int)
```

# GDB

```bash
ubuntu@ubuntu:~/Desktop/vox2mesh/build/vox2obj$ gdb --args ./afl_vox2obj out/default/crashes/id\:000000\,sig\:11\,src\:000002\,time\:9972\,execs\:836\,op\:havoc\,rep\:4 
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./afl_vox2obj...
gdb-peda$ r 
Starting program: /home/ubuntu/Desktop/vox2mesh/build/vox2obj/afl_vox2obj out/default/crashes/id:000000,sig:11,src:000002,time:9972,execs:836,op:havoc,rep:4
Version: 150
ChunkId: MAIN
399 voxels

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x9070b10 
RBX: 0x9070b0b 
RCX: 0x421ca0 --> 0x10001000000 
RDX: 0x9070b0b 
RSI: 0x635784 --> 0x6510000000b 
RDI: 0x7ffff6f8d0e0 
RBP: 0x7fffffffdc60 --> 0x7fffffffdce0 --> 0x1 
RSP: 0x7ffff6f8d0e0 
RIP: 0x40ae33 (<VoxReader::readChunk(unsigned char const*, unsigned int)+163>:	call   0x4051c0 <memcpy@plt>)
R8 : 0x634b38 --> 0x8070734 
R9 : 0x18f 
R10: 0xfffffffffffff04a 
R11: 0x7ffff7b066d0 (<__GI___libc_free>:	endbr64)
R12: 0x4203b8 --> 0x421ca0 --> 0x10001000000 
R13: 0x9 ('\t')
R14: 0x7fffffffdda0 --> 0x1400000014 
R15: 0x7ffff6f8d0e0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40ae2a <VoxReader::readChunk(unsigned char const*, unsigned int)+154>:	mov    r14,rdi
   0x40ae2d <VoxReader::readChunk(unsigned char const*, unsigned int)+157>:	mov    rdi,r15
   0x40ae30 <VoxReader::readChunk(unsigned char const*, unsigned int)+160>:	mov    rbx,rdx
=> 0x40ae33 <VoxReader::readChunk(unsigned char const*, unsigned int)+163>:	call   0x4051c0 <memcpy@plt>
   0x40ae38 <VoxReader::readChunk(unsigned char const*, unsigned int)+168>:	lea    rsi,[rbp-0x60]
   0x40ae3c <VoxReader::readChunk(unsigned char const*, unsigned int)+172>:	mov    rdi,r14
   0x40ae3f <VoxReader::readChunk(unsigned char const*, unsigned int)+175>:	mov    r14,QWORD PTR [rbp-0x38]
   0x40ae43 <VoxReader::readChunk(unsigned char const*, unsigned int)+179>:	mov    rdx,r15
Guessed arguments:
arg[0]: 0x7ffff6f8d0e0 
arg[1]: 0x635784 --> 0x6510000000b 
[------------------------------------stack-------------------------------------]
Invalid $SP address: 0x7ffff6f8d0e0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x000000000040ae33 in VoxReader::readChunk (this=0x7fffffffdda0, bytes=bytes@entry=0x635778 "\v\b\a\t\v\v\a\t\v\t\a\t\v", size=size@entry=0x9) at /home/ubuntu/Desktop/vox2mesh/VoxReader.cpp:139
139	            memcpy(&chunkContent, bytes + 12, chunkContentSize);

```

In original code 139, you can see this is stack overflow caused by incorrect use of memcpy() funciton, SP pointer can't point correct address.
