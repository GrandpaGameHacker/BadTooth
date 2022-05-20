from ctypes import *
from ctypes.wintypes import *
from .winnt import *

QWORD = c_longlong


class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID),
        ("SizeOfImage", DWORD),
        ("EntryPoint", LPVOID)
    ]

    @property
    def base_address(self):
        return self.lpBaseOfDll

    @property
    def size(self):
        return self.SizeOfImage

    @property
    def end_address(self):
        return self.SizeOfImage + self.lpBaseOfDll


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


class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL)
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

    @property
    def name(self):
        return self.szExeFile.decode("ASCII")

    @property
    def pid(self):
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

    @property
    def name(self):
        return self.szModule.decode("ASCII")

    @property
    def path(self):
        return self.szExePath.decode("ASCII")

    @property
    def base_address(self):
        return addressof(self.modBaseAddr.contents)

    @property
    def end_address(self):
        return addressof(self.modBaseAddr.contents) + self.modBaseSize - 1

    def get_memory_range(self):
        mem_range = (self.base_address, self.modBaseSize - 1)
        return mem_range

    @property
    def size(self):
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

    @property
    def tid(self):
        return self.th32ThreadID

    @property
    def owner_pid(self):
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

    @property
    def base_address(self):
        return self.BaseAddress

    @property
    def end_address(self):
        return self.BaseAddress + self.RegionSize

    def get_memory_range(self):
        mem_range = (self.base_address, self.RegionSize)
        return mem_range

    @property
    def protection(self):
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


class EXCEPTION_RECORD(Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", c_void_p),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", POINTER(ULONG))
]


class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD)
    ]


class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID)
    ]


class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD)
    ]


class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD)
    ]


class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD)
    ]


class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD)
    ]


class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID)
    ]


class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", QWORD),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD)
    ]


class RIP_INFO(Structure):
    _fields_ = [
        ("dwError", DWORD),
        ("dwType", DWORD)
    ]


class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", DEBUG_EVENT_UNION)
    ]

    @property
    def event_code(self):
        return self.dwDebugEventCode

    @property
    def process_id(self):
        return self.dwProcessId

    @property
    def thread_id(self):
        return self.dwThreadId

    @property
    def exception_code(self):
        return self.u.Exception.ExceptionRecord.ExceptionCode

    @property
    def exception_address(self):
        return self.u.Exception.ExceptionRecord.ExceptionAddress


# intel 32bit


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


class Dr7c(Structure):
    _fields_ = [
        ("l0", c_ulong, 1),
        ("g0", c_ulong, 1),
        ("l1", c_ulong, 1),
        ("g1", c_ulong, 1),
        ("l2", c_ulong, 1),
        ("g2", c_ulong, 1),
        ("l3", c_ulong, 1),
        ("g3", c_ulong, 1),
        ("le", c_ulong, 1),
        ("ge", c_ulong, 1),
        ("reserved1", c_ulong, 1),
        ("rtm", c_ulong, 1),
        ("reserved2", c_ulong, 1),
        ("gd", c_ulong, 1),
        ("reserved3", c_ulong, 2),
        ("rw0", c_ulong, 2),
        ("len0", c_ulong, 2),
        ("rw1", c_ulong, 2),
        ("len1", c_ulong, 2),
        ("rw2", c_ulong, 2),
        ("len2", c_ulong, 2),
        ("rw3", c_ulong, 2),
        ("len3", c_ulong, 2)
    ]


class Dr7u_32(Union):
    _fields_ = [
        ("all", DWORD),
        ("fields", Dr7c)
    ]


class Dr7u_64(Union):
    _fields_ = [
        ("all", QWORD),
        ("fields", Dr7c)
    ]


class CONTEXT32(Structure):
    _pack_ = 4
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", Dr7u_32),
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

    def clear_all_Drx(self):
        self.Dr0 = 0
        self.Dr1 = 0
        self.Dr2 = 0
        self.Dr3 = 0
        self.Dr6 = 0
        self.Dr7.all = 0

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
        ("Dr7", Dr7u_64),
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

    def clear_all_Drx(self):
        self.Dr0 = 0
        self.Dr1 = 0
        self.Dr2 = 0
        self.Dr3 = 0
        self.Dr6 = 0
        self.Dr7.all = 0


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
