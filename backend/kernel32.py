from ctypes import *
from ctypes.wintypes import *
from .winnt_constants import *
from . import winerror_constants
QWORD = c_longlong
kernel32 = WinDLL("kernel32", use_last_error=True)


def report_last_error():
    print(WinError(get_last_error()))


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


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", ULONG),
        ("StatusWord", ULONG),
        ("TagWord", ULONG),
        ("ErrorOffset", ULONG),
        ("ErrorSelector", ULONG),
        ("DataOffset", ULONG),
        ("DataSelector", ULONG),
        ("RegisterArea", CHAR * 80),
        ("Cr0NpxState", ULONG)
    ]

# intel64


class CONTEXT64(Structure):
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


# internal function definitions
__GetSystemInfo = kernel32.GetSystemInfo

__GetProcAddress = kernel32.GetProcAddress
__GetProcAddress.argtypes = [HMODULE, LPCSTR]
__GetProcAddress.restype = c_void_p

__GetModuleHandle = kernel32.GetModuleHandleA
__GetModuleHandle.argtypes = [LPCSTR]
__GetModuleHandle.restype = HMODULE

__OpenProcess = kernel32.OpenProcess

__OpenThread = kernel32.OpenThread
__OpenThread.argtypes = [DWORD, BOOL, DWORD]
__OpenThread.restype = HANDLE

__SuspendThread = kernel32.SuspendThread
__SuspendThread.argtypes = [HANDLE]
__SuspendThread.restype = DWORD

__ResumeThread = kernel32.ResumeThread
__ResumeThread.argtypes = [HANDLE]
__ResumeThread.restype = DWORD

__GetThreadContext = kernel32.GetThreadContext
__GetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
__GetThreadContext.restype = BOOL

__CloseHandle = kernel32.CloseHandle

__CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
__CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
__CreateToolhelp32Snapshot.restype = HANDLE

__Process32First = kernel32.Process32First
__Process32First.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
__Process32First.restype = BOOL

__Process32Next = kernel32.Process32Next
__Process32Next.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
__Process32Next.restype = BOOL

__Module32First = kernel32.Module32First
__Module32First.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
__Module32First.restype = BOOL

__Module32Next = kernel32.Module32Next
__Module32Next.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
__Module32Next.restype = BOOL

__Thread32First = kernel32.Thread32First
__Thread32First.argtypes = [HANDLE, POINTER(THREADENTRY32)]
__Thread32First.restype = BOOL

__Thread32Next = kernel32.Thread32Next
__Thread32Next.argtypes = [HANDLE, POINTER(THREADENTRY32)]
__Thread32Next.restype = BOOL

__ReadProcessMemory = kernel32.ReadProcessMemory
__ReadProcessMemory.argtypes = [
    HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
__ReadProcessMemory.restype = BOOL

__WriteProcessMemory = kernel32.WriteProcessMemory
__WriteProcessMemory.argtypes = [
    HANDLE, LPVOID, LPCVOID, c_size_t, POINTER(c_size_t)]
__WriteProcessMemory.restype = BOOL

__VirtualQueryEx = kernel32.VirtualQueryEx
__VirtualQueryEx.argtypes = [HANDLE, LPCVOID,
                             POINTER(MEMORY_BASIC_INFORMATION), c_size_t]
__VirtualQueryEx.restype = c_size_t

__VirtualProtectEx = kernel32.VirtualProtectEx
__VirtualProtectEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, PDWORD]
__VirtualProtectEx.restype = BOOL

__VirtualAllocEx = kernel32.VirtualAllocEx
__VirtualAllocEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, DWORD]
__VirtualAllocEx.restype = LPVOID

__VirtualFreeEx = kernel32.VirtualFreeEx
__VirtualFreeEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD]
__VirtualFreeEx.restype = BOOL

__CreateRemoteThreadEx = kernel32.CreateRemoteThreadEx
__CreateRemoteThreadEx.argtypes = [
    HANDLE, LPVOID, c_size_t, LPVOID, LPVOID, DWORD, LPVOID, LPDWORD]
__CreateRemoteThreadEx.restype = HANDLE

__IsWow64Process = kernel32.IsWow64Process
__IsWow64Process.argtypes = [HANDLE, PBOOL]
__IsWow64Process.restype = BOOL

__WaitForSingleObject = kernel32.WaitForSingleObject
__WaitForSingleObject.argtypes = [HANDLE, DWORD]
__WaitForSingleObject.restype = DWORD

__TerminateProcess = kernel32.TerminateProcess
__TerminateProcess.argtypes = [HANDLE, UINT]
__TerminateProcess.restype = BOOL

# external api


def GetSystemInfo():
    system_info = SYSTEM_INFO()
    __GetSystemInfo(byref(system_info))
    return system_info


def GetModuleHandle(module):
    c_data = c_char_p(bytes(module, "ASCII"))
    handle = __GetModuleHandle(c_data)
    if handle == winerror_constants.ERROR_INVALID_HANDLE:
        report_last_error()
    else:
        return handle


def GetProcAddress(module_handle, proc_name):
    c_data = c_char_p(bytes(proc_name, "ASCII"))
    address = __GetProcAddress(module_handle, c_data)
    if address == 0:
        report_last_error()
    else:
        return address


def CreateToolhelp32Snapshot(dwFlags, th32ProcessID):
    handle = __CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if handle == winerror_constants.ERROR_INVALID_HANDLE:
        report_last_error()
    else:
        return handle


def Process32First(hSnapshot):
    process_entry = PROCESSENTRY32()
    process_entry.dwSize = sizeof(PROCESSENTRY32)
    success = __Process32First(hSnapshot, byref(process_entry))
    if not success:
        report_last_error()
    else:
        return process_entry


def Process32Next(hSnapshot, process_entry):
    success = __Process32Next(hSnapshot, byref(process_entry))
    return success


def Thread32First(hSnapshot):
    thread_entry = THREADENTRY32()
    thread_entry.dwSize = sizeof(THREADENTRY32)
    success = __Thread32First(hSnapshot, byref(thread_entry))
    if not success:
        report_last_error()
    else:
        return thread_entry


def Thread32Next(hSnapshot, thread_entry):
    success = __Thread32Next(hSnapshot, byref(thread_entry))
    return success


def Module32First(hSnapshot):
    module_entry = MODULEENTRY32()
    module_entry.dwSize = sizeof(MODULEENTRY32)
    success = __Module32First(hSnapshot, byref(module_entry))
    if not success:
        report_last_error()
    else:
        return module_entry


def Module32Next(hSnapshot, module_entry):
    success = __Module32Next(hSnapshot, byref(module_entry))
    return success


def OpenProcess(pid, bInheritHandle=False):
    process_handle = __OpenProcess(
        PROCESS_ALL_ACCESS, bInheritHandle, pid)

    if process_handle == 0:
        report_last_error()
    return process_handle


def OpenThread(tid, bInheritHandle=False):
    thread_handle = __OpenThread(
        THREAD_ALL_ACCESS, bInheritHandle, tid)
    if thread_handle == 0:
        report_last_error()
    return thread_handle


def SuspendThread(thread_handle):
    result = __SuspendThread(thread_handle)
    if result != -1:
        return True
    else:
        report_last_error()
        return False


def ResumeThread(thread_handle):
    result = __ResumeThread(thread_handle)
    if result != -1:
        return True
    else:
        report_last_error()
        return False


def GetThreadContext(thread_handle):
    thread_context = CONTEXT64()
    thread_context.ContextFlags = CONTEXT_FULL
    result = __GetThreadContext(thread_handle, byref(thread_context))
    if result:
        return thread_context
    else:
        report_last_error()


def CloseHandle(handle):
    success = __CloseHandle(handle)
    if not success:
        report_last_error()
    return success


def ReadProcessMemory(process_handle, address, nSize):
    buffer = create_string_buffer(nSize)
    bytes_read = c_size_t()
    success = __ReadProcessMemory(
        process_handle, address, buffer, nSize, byref(bytes_read))
    if not success:
        report_last_error()
    else:
        return bytearray(buffer)


def WriteProcessMemory(process_handle, address, buffer):
    c_data = c_char_p(bytes(buffer))
    ptr_c_data = cast(c_data, POINTER(c_char))
    success = __WriteProcessMemory(
        process_handle, address, ptr_c_data, len(buffer), None)
    if not success:
        report_last_error()
    return success


def VirtualQueryEx(process_handle, address):
    mem_basic_info = MEMORY_BASIC_INFORMATION()
    success = __VirtualQueryEx(process_handle, address, byref(
        mem_basic_info), sizeof(mem_basic_info))
    if not success:
        report_last_error()
    else:
        return mem_basic_info


def VirtualProtectEx(process_handle, address, size, new_protect):
    old_protect = DWORD(0)
    success = __VirtualProtectEx(process_handle, address, size,
                                 new_protect, byref(old_protect))
    if success:
        return old_protect
    else:
        report_last_error()


def VirtualAllocEx(process_handle, address, size,
                   allocation_type=MEM_COMMIT,
                   protect=PAGE_EXECUTE_READWRITE):
    new_memory = __VirtualAllocEx(
        process_handle, address, size, allocation_type, protect)
    if not new_memory:
        report_last_error()
    else:
        return new_memory


def VirtualFreeEx(process_handle, address,
                  size=0, free_type=MEM_RELEASE):
    success = __VirtualFreeEx(process_handle, address, size, free_type)
    if not success:
        report_last_error()
    return success


def CreateRemoteThreadEx(process_handle, start_address,
                         parameter, creation_flags=0):
    handle = __CreateRemoteThreadEx(process_handle,
                                    0, 0, start_address,
                                    c_void_p(parameter),
                                    creation_flags, 0, DWORD(0))
    if handle == winerror_constants.ERROR_INVALID_HANDLE:
        report_last_error()
    else:
        return handle


def IsWow64Process(handle):
    result = BOOL(False)
    if __IsWow64Process(handle, byref(result)):
        return result
    else:
        report_last_error()
        return result


def WaitForSingleObject(object_handle, milliseconds):
    result = __WaitForSingleObject(object_handle, milliseconds)
    if result == WAIT_FAILED:
        report_last_error()
    return result


def TerminateProcess(process_handle, exit_code):
    success = __TerminateProcess(process_handle, exit_code)
    if not success:
        report_last_error()
    return success
