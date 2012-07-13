#!/usr/local/bin/python
import random

NOPS = [
["\x90", [ 'nop'], ], # nop
["\x97", ['eax', 'edi'], ], # xchg eax,edi
["\x96", ['eax', 'esi'], ], # xchg eax,esi
["\x95", ['eax', 'ebp'], ], # xchg eax,ebp
["\x93", ['eax', 'ebx'], ], # xchg eax,ebx
["\x92", ['eax', 'edx'], ], # xchg eax,edx
["\x91", ['eax', 'ecx'], ], # xchg eax,ecx
["\x99", ['edx'], ], # cdq
["\x4d", ['ebp'], ], # dec ebp
["\x48", ['eax'], ], # dec eax
["\x47", ['edi'], ], # inc edi
["\x4f", ['edi'], ], # dec edi
["\x40", ['eax'], ], # inc eax
["\x41", ['ecx'], ], # inc ecx
["\x37", ['eax'], ], # aaa
["\x3f", ['eax'], ], # aas
["\x27", ['eax'], ], # daa
["\x2f", ['eax'], ], # das
["\x46", ['esi'], ], # inc esi
["\x4e", ['esi'], ], # dec esi

#flag foo fixme
#direction flag should be ok to change
["\xfc", [ ], ], # cld
["\xfd", [ ], ], # std
#carry flag should be ok to change
["\xf8", [ ], ], # clc
["\xf9", [ ], ], # stc
["\xf5", [ ], ], # cmc

["\x98", ['eax'], ], # cwde
["\x9f", ['eax'], ], # lahf
["\x4a", ['edx'], ], # dec edx
["\x44", ['esp'], ], # inc esp
["\x42", ['edx'], ], # inc edx
["\x43", ['ebx'], ], # inc ebx
["\x49", ['ecx'], ], # dec ecx
["\x4b", ['ebx'], ], # dec ebx
["\x45", ['ebp'], ], # inc ebp
["\x4c", ['esp'], ], # dec esp
["\x9b", [ ], ], # wait
["\x60", ['esp'], ], # pusha
["\x0e", ['esp'], ], # push cs
["\x1e", ['esp'], ], # push ds
["\x50", ['esp'], ], # push eax
["\x55", ['esp'], ], # push ebp
["\x53", ['esp'], ], # push ebx
["\x51", ['esp'], ], # push ecx
["\x57", ['esp'], ], # push edi
["\x52", ['esp'], ], # push edx
["\x06", ['esp'], ], # push es
["\x56", ['esp'], ], # push esi
["\x54", ['esp'], ], # push esp
["\x16", ['esp'], ], # push ss
["\x58", ['esp', 'eax'], ], # pop eax
["\x5d", ['esp', 'ebp'], ], # pop ebp
["\x5b", ['esp', 'ebx'], ], # pop ebx
["\x59", ['esp', 'ecx'], ], # pop ecx
["\x5f", ['esp', 'edi'], ], # pop edi
["\x5a", ['esp', 'edx'], ], # pop edx
["\x5e", ['esp', 'esi'], ], # pop esi
["\xd6", ['eax'], ], # salc
]

def NopGenerator( length):
    nops = [x[0] for x in NOPS]
    nopsled = ""
    for i in range(length):
        nopsled += random.choice(nops)
    return nopsled

def nopInPython(nopsled):
    return

def nopInC(nopsled):
    nopCodes =  "// total %d (0x%x) bytes\n" % (len(nopsled), len(nopsled))
    nopCodes += "unsigned char NOP[] = \n"
    for i in range(0, len(nopsled), 8):
        nopCodes += "\""
        nopCodes += "\\x" + "\\x".join( ["%02x" % ord(x) for x in nopsled[i:i+8]])
        nopCodes += "\"\n"
    nopCodes = nopCodes[:-1] + ";\n"
    return nopCodes

if __name__ == "__main__":
    #print NOPS
    nopsled = NopGenerator( 0x80)
    print nopInC(nopsled)

