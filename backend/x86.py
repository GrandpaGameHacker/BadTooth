from capstone import *
from keystone import *


class Asm:
    """
    Class to assemble x86/x86-64 instructions into machine code
    Asm(mode_32: bool) -> Asm
    """
    def __init__(self, mode_32):
        if mode_32:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        else:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    def assemble(self, code):
        """
        Generates machine code from instructions
        assemble(code: str) -> bytes
        """
        return bytes(self.ks.asm(code)[0])


class Dsm:
    """
    Class to disassemble x86/x86-64 instructions
    Dsm(mode_32: bool) -> Dsm
    """
    def __init__(self, mode_32):
        if mode_32:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)

    def dis(self, code, address, count=0):
        """
        Disassembles code via a generator, each generated instruction
        is of type CsInsn (capstone object)
        Dsm.dis(code: bytes-like-object, address: int, count=0: int) -> Generator(CsInsn)

        This function returns more details than dis_lite, especially when details mode is on.
        """
        dis_gen = self.cs.disasm(code, address, count=count)
        return dis_gen

    def dis_all(self, code, address, count=0):
        """
        Disassembles all of the code and returns a list of CsInsn objects
        Dsm.dis_all(code: bytes-like-object, address: int, count=0: int) -> list([CsInsn,...])

        This function returns more details than dis_lite, especially when details mode is on.
        """
        dis_gen = self.cs.disasm(code, address, count=count)
        return [asm for asm in dis_gen]

    def dis_lite(self, code, address):
        """
        Disassembles code via a generator, each generated instruction is in string form
        and resides in a tuple, faster than other disassembly modes
        Dsm.dis_lite(code: bytes-like-object, address: int) -> Generator(Tuple(instruction_details...))
        """
        dis_gen = self.cs.disasm_lite(code, address)
        return dis_gen

    def dis_lite_all(self, code, address):
        """
        Disassembles all of the code and returns a list of instructions in string form
        """
        dis_gen = self.cs.disasm_lite(code, address)
        return [asm for asm in dis_gen]

    def enable_details(self):
        """
        Enables extra details in the disassembly, but slows down processing.
        """
        self.cs.detail = True

    def disable_details(self):
        """
        Disables extra details in the disassembly.
        """
        self.cs.detail = False
