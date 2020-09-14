from ctypes import *
from ctypes.wintypes import *
from .winnt_constants import *
QWORD = c_longlong


class SYSTEM_INFO(Structure):
    _fields_ = [
        ("dwOemId", DWORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", POINTER(DWORD)),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", POINTER(ULONG)),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", CHAR * 260)  # MAX_PATH
    ]

    def get_name(self):
        return self.szExeFile.decode("ASCII")

    def get_pid(self):
        return self.th32ProcessID


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", PBYTE),
        ("modBaseSize", DWORD),
        ("hModule", HMODULE),
        ("szModule", CHAR * 256),
        ("szExePath", CHAR * 260)
    ]

    def get_name(self):
        return self.szModule.decode("ASCII")

    def get_path(self):
        return self.szExePath.decode("ASCII")

    def get_base_address(self):
        return addressof(self.modBaseAddr.contents)

    def get_end_address(self):
        return addressof(self.modBaseAddr.contents) + self.modBaseSize - 1

    def get_memory_range(self):
        mem_range = (self.get_base_address(), self.modBaseSize - 1)
        return mem_range

    def get_size(self):
        return self.modBaseSize


class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", LONG),
        ("tpDeltaPri", LONG),
        ("dwFlags", DWORD)
    ]

    def get_tid(self):
        return self.th32ThreadID

    def get_owner_pid(self):
        return self.th32OwnerProcessID


protections = {
    0: "invalid",
    PAGE_READONLY: "r",
    PAGE_READWRITE: "rw",
    PAGE_WRITECOPY: "wc",
    PAGE_WRITECOMBINE: "wc+",
    PAGE_EXECUTE: "x",
    PAGE_EXECUTE_READ: "rx",
    PAGE_EXECUTE_READWRITE: "rwx",
    PAGE_EXECUTE_WRITECOPY: "wcx",
    PAGE_NOCACHE: "nc",
    PAGE_NOACCESS: "n"
}


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("Allocationprotect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)]

    def get_base_address(self):
        return self.BaseAddress

    def get_end_address(self):
        return self.BaseAddress + self.RegionSize

    def get_memory_range(self):
        mem_range = (self.get_base_address(), self.RegionSize)
        return mem_range

    def get_protect(self):
        protect = self.Protect
        guarded = False
        if protect & PAGE_GUARD:
            protect = protect ^ PAGE_GUARD
            guarded = True
        protect_s = protections[protect]
        if guarded:
            protect_s += "g"
        return protect_s

    def is_readable(self):
        protect = self.Protect
        guarded = bool(protect & PAGE_GUARD)
        noaccess = bool(protect & PAGE_NOACCESS)
        if guarded or noaccess:
            return False
        else:
            return True


class WOW64_FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD)
    ]


# intel 32bit


class CONTEXT32(Structure):
    _pack_ = 4
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512)
    ]



# intel 64bit

class CONTEXT64(Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", QWORD),
        ("P2Home", QWORD),
        ("P3Home", QWORD),
        ("P4Home", QWORD),
        ("P5Home", QWORD),
        ("P6Home", QWORD),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("Dr0", QWORD),
        ("Dr1", QWORD),
        ("Dr2", QWORD),
        ("Dr3", QWORD),
        ("Dr6", QWORD),
        ("Dr7", QWORD),
        ("Rax", QWORD),
        ("Rcx", QWORD),
        ("Rdx", QWORD),
        ("Rbx", QWORD),
        ("Rsp", QWORD),
        ("Rbp", QWORD),
        ("Rsi", QWORD),
        ("Rdi", QWORD),
        ("R8", QWORD),
        ("R9", QWORD),
        ("R10", QWORD),
        ("R11", QWORD),
        ("R12", QWORD),
        ("R13", QWORD),
        ("R14", QWORD),
        ("R15", QWORD),
        ("Rip", QWORD),
        ("Xmm0", c_float * 4),  # ugh
        ("Xmm1", c_float * 4),
        ("Xmm2", c_float * 4),
        ("Xmm3", c_float * 4),
        ("Xmm4", c_float * 4),
        ("Xmm5", c_float * 4),
        ("Xmm6", c_float * 4),
        ("Xmm7", c_float * 4),
        ("Xmm8", c_float * 4),
        ("Xmm9", c_float * 4),
        ("Xmm10", c_float * 4),
        ("Xmm11", c_float * 4),
        ("Xmm12", c_float * 4),
        ("Xmm13", c_float * 4),
        ("Xmm14", c_float * 4),
        ("Xmm15", c_float * 4),
        ("VectorRegister", c_float * 104),
        ("VectorControl", QWORD),
        ("DebugControl", QWORD),
        ("LastBranchToRip", QWORD),
        ("LastBranchFromRip", QWORD),
        ("LastExceptionToRip", QWORD),
        ("LastExceptionFromRip", QWORD)
    ]


class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL)
    ]


class STARTUPINFOA(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPSTR),
        ("lpDesktop", LPSTR),
        ("lpTitle", LPSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE)
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]
