from ctypes import *
from ctypes.wintypes import *
import winerror
import winnt
kernel32 = WinDLL("kernel32", use_last_error=True)

__OpenProcess = windll.kernel32.OpenProcess
__CloseHandle = windll.kernel32.CloseHandle

# tlhelp32 structs
MAX_PATH = CHAR * 260


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
        ("szExeFile", MAX_PATH)
    ]


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

__VirtualQuery = kernel32.VirtualQueryEx
__VirtualQuery.argtypes = [HANDLE, LPCVOID, POINTER(Region), c_size_t]
__VirtualQuery.restype = c_size_t

__VirtualAlloc = kernel32.VirtualAllocEx
__VirtualAlloc.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, DWORD]
__VirtualAlloc.restype = LPVOID

__VirtualFree = kernel32.VirtualFreeEx
__VirtualFree.argtypes = [HANDLE, LPVOID, c_size_t, DWORD]
__VirtualFree.restype = BOOL


def CreateToolhelp32Snapshot(dwFlags, th32ProcessID):
    handle = __CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if handle == winerror.ERROR_INVALID_HANDLE:
        print(WinError(get_last_error()))
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
    if not success:
        print(WinError(get_last_error()))
    return success


def OpenProcess(pid, bInheritHandle=False):
    process_handle = __OpenProcess(
        winnt.PROCESS_ALL_ACCESS, bInheritHandle, pid)

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
    success = __ReadProcessMemory(process_handle, address, nSize, 0)
    if not success:
        print(WinError(get_last_error()))
    else:
        return bytearray(buffer)


def WriteProcessMemory(process_handle, address, buffer):
    c_data = c_char_p(bytes(buffer))
    ptr_c_data = cast(c_data, POINTER(c_char))
    success = __WriteProcessMemory(
        process_handle, address, ptr_c_data, len(buffer), 0)
    if not success:
        print(WinError(get_last_error()))
    return success
