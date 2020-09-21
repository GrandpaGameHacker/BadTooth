from ctypes import *
from ctypes.wintypes import *
from .winnt_constants import *
from . import winerror_constants
from . kernel32_structs import *
kernel32 = WinDLL("kernel32", use_last_error=True)


def report_last_error():
    print(WinError(get_last_error()))


# internal function definitions
__GetSystemInfo = kernel32.GetSystemInfo
__GetProcAddress = kernel32.GetProcAddress
__GetProcAddress.argtypes = [HMODULE, LPCSTR]
__GetProcAddress.restype = c_void_p

__GetModuleHandle = kernel32.GetModuleHandleA
__GetModuleHandle.argtypes = [LPCSTR]
__GetModuleHandle.restype = HMODULE

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcessId = kernel32.GetCurrentProcessId

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
#
# REPLACE SUSPEND/RESUME with NtSuspendProcess, NtResumeProcess (Speed problem)
#
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

__CreateProcessA = kernel32.CreateProcessA
__CreateProcessA.argtypes = [LPCSTR, LPSTR, POINTER(SECURITY_ATTRIBUTES),
                             POINTER(SECURITY_ATTRIBUTES), BOOL,
                             DWORD, LPVOID, LPCSTR,
                             POINTER(STARTUPINFOA),
                             POINTER(PROCESS_INFORMATION)
                             ]
__CreateProcessA.restype = BOOL

# debugging and thread_hijack
__DebugActiveProcess = kernel32.DebugActiveProcess
__DebugActiveProcess.argtypes = [DWORD]
__DebugActiveProcess.restype = BOOL

__DebugActiveProcessStop = kernel32.DebugActiveProcessStop
__DebugActiveProcessStop.argtypes = [DWORD]
__DebugActiveProcessStop.restype = BOOL

__DebugBreakProcess = kernel32.DebugBreakProcess
__DebugBreakProcess.argtypes = [HANDLE]
__DebugBreakProcess.restype = BOOL

DebugSetProcessKillOnExit = kernel32.DebugSetProcessKillOnExit
DebugSetProcessKillOnExit.argtypes = [BOOL]
DebugSetProcessKillOnExit.restype = BOOL

__ContinueDebugEvent = kernel32.ContinueDebugEvent
__ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
__ContinueDebugEvent.restype = BOOL

__WaitForDebugEvent = kernel32.WaitForDebugEvent
__WaitForDebugEvent.argtypes = [POINTER(DEBUG_EVENT), DWORD]
__WaitForDebugEvent.restype = BOOL

__GetThreadContext = kernel32.GetThreadContext
__GetThreadContext.argtypes = [DWORD, POINTER(CONTEXT64)]
__GetThreadContext.restype = BOOL

__SetThreadContext = kernel32.SetThreadContext
__SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
__SetThreadContext.restype = BOOL

__Wow64GetThreadContext = kernel32.Wow64GetThreadContext
__Wow64GetThreadContext.argtypes = [DWORD, POINTER(CONTEXT32)]
__Wow64GetThreadContext.restype = BOOL

__Wow64SetThreadContext = kernel32.Wow64SetThreadContext
__Wow64SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT32)]

__FlushInstructionCache = kernel32.FlushInstructionCache
__FlushInstructionCache.argtypes = [HANDLE, LPCVOID, c_size_t]
__FlushInstructionCache.restype = BOOL
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


def CreateToolhelp32Snapshot(flags, process_id):
    handle = __CreateToolhelp32Snapshot(flags, process_id)
    if handle == winerror_constants.ERROR_INVALID_HANDLE:
        report_last_error()
    else:
        return handle


def Process32First(h_snapshot):
    process_entry = PROCESSENTRY32()
    process_entry.dwSize = sizeof(PROCESSENTRY32)
    success = __Process32First(h_snapshot, byref(process_entry))
    if not success:
        report_last_error()
    else:
        return process_entry


def Process32Next(h_snapshot, process_entry):
    success = __Process32Next(h_snapshot, byref(process_entry))
    return success


def Thread32First(h_snapshot):
    thread_entry = THREADENTRY32()
    thread_entry.dwSize = sizeof(THREADENTRY32)
    success = __Thread32First(h_snapshot, byref(thread_entry))
    if not success:
        report_last_error()
    else:
        return thread_entry


def Thread32Next(h_snapshot, thread_entry):
    success = __Thread32Next(h_snapshot, byref(thread_entry))
    return success


def Module32First(h_snapshot):
    module_entry = MODULEENTRY32()
    module_entry.dwSize = sizeof(MODULEENTRY32)
    success = __Module32First(h_snapshot, byref(module_entry))
    if not success:
        report_last_error()
    else:
        return module_entry


def Module32Next(h_snapshot, module_entry):
    success = __Module32Next(h_snapshot, byref(module_entry))
    return success


def OpenProcess(pid, b_inherit_handle=False):
    process_handle = __OpenProcess(
        PROCESS_ALL_ACCESS, b_inherit_handle, pid)

    if process_handle == 0:
        report_last_error()
    return process_handle


def OpenThread(tid, b_inherit_handle=False):
    thread_handle = __OpenThread(
        THREAD_ALL_ACCESS, b_inherit_handle, tid)
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


def CloseHandle(handle):
    success = __CloseHandle(handle)
    if not success:
        report_last_error()
    return success


def ReadProcessMemory(process_handle, address, n_size):
    buffer = create_string_buffer(n_size)
    bytes_read = c_size_t()
    success = __ReadProcessMemory(
        process_handle, address, buffer, n_size, byref(bytes_read))
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


def CreateProcess(application_name, command_line, flags):
    process_sec = SECURITY_ATTRIBUTES()
    thread_sec = SECURITY_ATTRIBUTES()
    startup_info = STARTUPINFOA()
    startup_info.cb = sizeof(startup_info)
    process_info = PROCESS_INFORMATION()
    application_name = c_char_p(application_name.encode("ASCII"))
    command_line = c_char_p(command_line.encode("ASCII"))
    success = __CreateProcessA(application_name, command_line,
                               byref(process_sec),
                               byref(thread_sec), False, flags, 0, LPCSTR(0),
                               byref(startup_info), byref(process_info))
    if not success:
        report_last_error()
        return None
    else:
        CloseHandle(process_info.hProcess)
        CloseHandle(process_info.hThread)
        return process_info.dwProcessId


def TerminateProcess(process_handle, exit_code):
    success = __TerminateProcess(process_handle, exit_code)
    if not success:
        report_last_error()
    return success


def GetThreadContext(is_32bit, thread_handle):
    if is_32bit:
        thread_context = CONTEXT32()
        thread_context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        result = __Wow64GetThreadContext(thread_handle, byref(thread_context))
    else:
        thread_context = CONTEXT64()
        thread_context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        result = __GetThreadContext(thread_handle, byref(thread_context))
    if result:
        return thread_context
    else:
        report_last_error()


def SetThreadContext(is_32bit, thread_handle, thread_context):
    if is_32bit:
        result = __Wow64SetThreadContext(thread_handle, thread_context)
    else:
        result = __SetThreadContext(thread_handle, thread_context)
    if not result:
        report_last_error()
    return result


def DebugActiveProcess(process_id):
    success = __DebugActiveProcess(process_id)
    if not success:
        report_last_error()
    return success


def DebugActiveProcessStop(process_id):
    success = __DebugActiveProcessStop(process_id)
    if not success:
        report_last_error()
    return success


def DebugBreakProcess(process_handle):
    success = __DebugBreakProcess(process_handle)
    if not success:
        report_last_error()
    return success


def WaitForDebugEvent(debug_event, milliseconds):
    success = __WaitForDebugEvent(byref(debug_event), milliseconds)
    if not success:
        report_last_error()
    return success


def ContinueDebugEvent(process_id, thread_id, continue_status):
    success = __ContinueDebugEvent(process_id, thread_id, continue_status)
    if not success:
        report_last_error()
    return success


def FlushInstructionCache(process_handle):
    success = __FlushInstructionCache(process_handle, 0, 0)
    if not success:
        report_last_error()
    return success
