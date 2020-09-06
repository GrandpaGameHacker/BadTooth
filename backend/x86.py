from capstone import *
from keystone import *


class Asm():
    def __init__(self, mode_64):
        if mode_64:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        else:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)

    def assemble(self, code):
        return self.ks.asm(code)


class Dsm():
    def __init__(self, mode_64):
        if mode_64:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)

    def dis(self, code, address, count=0):
        dis_gen = self.cs.disasm(code, address, count=count)
        return dis_gen

    def dis_all(self, code, address, count=0):
        dis_gen = self.cs.disasm(code, address, count=count)
        return [asm for asm in dis_gen]

    def dis_lite(self, code, address):
        dis_gen = self.cs.disasm_lite(code, address)
        return dis_gen

    def dis_lite_all(self, code, address):
        dis_gen = self.cs.disasm_lite(code, address)
        return [asm for asm in dis_gen]

    def enable_details(self):
        self.cs.detail = True

    def disable_details(self):
        self.cs.detail = False
