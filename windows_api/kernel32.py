from ctypes import *
from ctypes.wintypes import *
from .winnt_constants import *
from . import winerror_constants
kernel32 = WinDLL("kernel32", use_last_error=True)


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


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("Allocationprotect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)]


# internal function definitions
__GetSystemInfo = kernel32.GetSystemInfo

__OpenProcess = kernel32.OpenProcess
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

# external api


def GetSystemInfo():
    system_info = SYSTEM_INFO()
    __GetSystemInfo(byref(system_info))
    return system_info


def CreateToolhelp32Snapshot(dwFlags, th32ProcessID):
    handle = __CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if handle == winerror_constants.ERROR_INVALID_HANDLE:
        print(WinError(get_last_error()))
    else:
        return handle


def Process32First(hSnapshot):
    process_entry = PROCESSENTRY32()
    process_entry.dwSize = sizeof(PROCESSENTRY32)
    success = __Process32First(hSnapshot, byref(process_entry))
    if not success:
        print(WinError(get_last_error()))
    else:
        return process_entry


def Process32Next(hSnapshot, process_entry):
    success = __Process32Next(hSnapshot, byref(process_entry))
    # if not success:
    # print(WinError(get_last_error()))
    return success


def OpenProcess(pid, bInheritHandle=False):
    process_handle = __OpenProcess(
        PROCESS_ALL_ACCESS, bInheritHandle, pid)

    if process_handle == 0:
        print(WinError(get_last_error()))
    return process_handle


def CloseHandle(handle):
    success = __CloseHandle(handle)
    if not success:
        print(WinError(get_last_error()))
    return success


def ReadProcessMemory(process_handle, address, nSize):
    buffer = create_string_buffer(nSize)
    bytes_read = c_size_t()
    success = __ReadProcessMemory(
        process_handle, address, buffer, nSize, byref(bytes_read))
    if not success:
        print(WinError(get_last_error()))
    else:
        return bytearray(buffer)


def WriteProcessMemory(process_handle, address, buffer):
    c_data = c_char_p(bytes(buffer))
    ptr_c_data = cast(c_data, POINTER(c_char))
    success = __WriteProcessMemory(
        process_handle, address, ptr_c_data, len(buffer), None)
    if not success:
        print(WinError(get_last_error()))
    return success


def VirtualQueryEx(process_handle, address):
    mem_basic_info = MEMORY_BASIC_INFORMATION()
    success = __VirtualQueryEx(process_handle, address, byref(
        mem_basic_info), sizeof(mem_basic_info))
    if not success:
        print(WinError(get_last_error()))
    else:
        return mem_basic_info


def VirtualAllocEx(process_handle, address, size,
                   allocation_type=MEM_COMMIT,
                   protect=PAGE_EXECUTE_READWRITE):
    new_memory = __VirtualAllocEx(
        process_handle, address, size, allocation_type, protect)
    if not new_memory:
        print(WinError(get_last_error()))
    else:
        return new_memory


def VirtualFreeEx(process_handle, address,
                  size=0, free_type=MEM_RELEASE):
    success = __VirtualFreeEx(process_handle, address, size, free_type)
    if not success:
        print(WinError(get_last_error()))
    return success


def CreateRemoteThreadEx(process_handle, start_address,
                         parameter, creation_flags=0):
    handle = __CreateRemoteThreadEx(process_handle,
                                    0, 0, start_address,
                                    byref(DWORD(parameter)),
                                    creation_flags, 0, DWORD(0))
    if handle == winerror_constants.ERROR_INVALID_HANDLE:
        print(WinError(get_last_error()))
    else:
        return handle
