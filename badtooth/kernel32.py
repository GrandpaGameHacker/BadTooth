from ctypes import *
from ctypes.wintypes import *
from . import winnt
from . import winerror
from . kernel32_structs import *
kernel32 = WinDLL("kernel32", use_last_error=True)


def report_last_error():
    print(WinError(get_last_error()))


# internal function definitions

# GetSystemInfo(lpSystemInfo);
__GetSystemInfo = kernel32.GetSystemInfo
__GetSystemInfo.argtypes = [POINTER(SYSTEM_INFO)]

# GetProcAddress(hModule, lpProcName);
__GetProcAddress = kernel32.GetProcAddress
__GetProcAddress.argtypes = [HMODULE, LPCSTR]
__GetProcAddress.restype = c_void_p

# GetModuleHandle(lpModuleName);
__GetModuleHandle = kernel32.GetModuleHandleA
__GetModuleHandle.argtypes = [LPCSTR]
__GetModuleHandle.restype = HMODULE

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcessId = kernel32.GetCurrentProcessId

# OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId );
__OpenProcess = kernel32.OpenProcess
__OpenProcess.argtypes = [DWORD, BOOL, DWORD]
__OpenProcess.restype = HANDLE

# OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId );
__OpenThread = kernel32.OpenThread
__OpenThread.argtypes = [DWORD, BOOL, DWORD]
__OpenThread.restype = HANDLE

# SuspendThread(hThread );
__SuspendThread = kernel32.SuspendThread
__SuspendThread.argtypes = [HANDLE]
__SuspendThread.restype = DWORD

# ResumeThread(hThread );
__ResumeThread = kernel32.ResumeThread
__ResumeThread.argtypes = [HANDLE]
__ResumeThread.restype = DWORD

# CloseHandle(hObject );
__CloseHandle = kernel32.CloseHandle
__CloseHandle.argtypes = [HANDLE]
__CloseHandle.restype = BOOL

# CreateToolhelp32Snapshot(dwFlags, th32ProcessID );
__CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
__CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
__CreateToolhelp32Snapshot.restype = HANDLE

# Process32First(hSnapshot, lppe);
__Process32First = kernel32.Process32First
__Process32First.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
__Process32First.restype = BOOL

# Process32Next(hSnapshot, lppe);
__Process32Next = kernel32.Process32Next
__Process32Next.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
__Process32Next.restype = BOOL

# Module32First(hSnapshot, lpme );
__Module32First = kernel32.Module32First
__Module32First.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
__Module32First.restype = BOOL

# Module32Next(hSnapshot, lpme );
__Module32Next = kernel32.Module32Next
__Module32Next.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
__Module32Next.restype = BOOL

# Thread32First(hSnapshot, lpte );
__Thread32First = kernel32.Thread32First
__Thread32First.argtypes = [HANDLE, POINTER(THREADENTRY32)]
__Thread32First.restype = BOOL

# Thread32Next(hSnapshot, lpte );
__Thread32Next = kernel32.Thread32Next
__Thread32Next.argtypes = [HANDLE, POINTER(THREADENTRY32)]
__Thread32Next.restype = BOOL

# ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpNumberOfBytesRead );
__ReadProcessMemory = kernel32.ReadProcessMemory
__ReadProcessMemory.argtypes = [
    HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
__ReadProcessMemory.restype = BOOL

# WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpNumberOfBytesWritten );
__WriteProcessMemory = kernel32.WriteProcessMemory
__WriteProcessMemory.argtypes = [
    HANDLE, LPVOID, LPCVOID, c_size_t, POINTER(c_size_t)]
__WriteProcessMemory.restype = BOOL

# VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength );
__VirtualQueryEx = kernel32.VirtualQueryEx
__VirtualQueryEx.argtypes = [HANDLE, LPCVOID,
                             POINTER(MEMORY_BASIC_INFORMATION), c_size_t]
__VirtualQueryEx.restype = c_size_t

# VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect );
__VirtualProtectEx = kernel32.VirtualProtectEx
__VirtualProtectEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, PDWORD]
__VirtualProtectEx.restype = BOOL

# VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect );
__VirtualAllocEx = kernel32.VirtualAllocEx
__VirtualAllocEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, DWORD]
__VirtualAllocEx.restype = LPVOID

# VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType );
__VirtualFreeEx = kernel32.VirtualFreeEx
__VirtualFreeEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD]
__VirtualFreeEx.restype = BOOL

# CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags,
# lpAttributeList, lpThreadId );
__CreateRemoteThreadEx = kernel32.CreateRemoteThreadEx
__CreateRemoteThreadEx.argtypes = [
    HANDLE, LPVOID, c_size_t, LPVOID, LPVOID, DWORD, LPVOID, LPDWORD]
__CreateRemoteThreadEx.restype = HANDLE

# IsWow64Process(hProcess, Wow64Process );
__IsWow64Process = kernel32.IsWow64Process
__IsWow64Process.argtypes = [HANDLE, PBOOL]
__IsWow64Process.restype = BOOL

# WaitForSingleObject(hHandle, dwMilliseconds );
__WaitForSingleObject = kernel32.WaitForSingleObject
__WaitForSingleObject.argtypes = [HANDLE, DWORD]
__WaitForSingleObject.restype = DWORD

# TerminateProcess(hProcess, uExitCode );
__TerminateProcess = kernel32.TerminateProcess
__TerminateProcess.argtypes = [HANDLE, UINT]
__TerminateProcess.restype = BOOL

# CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
# dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation );
__CreateProcessA = kernel32.CreateProcessA
__CreateProcessA.argtypes = [LPCSTR, LPSTR, POINTER(SECURITY_ATTRIBUTES),
                             POINTER(SECURITY_ATTRIBUTES), BOOL,
                             DWORD, LPVOID, LPCSTR,
                             POINTER(STARTUPINFOA),
                             POINTER(PROCESS_INFORMATION)
                             ]
__CreateProcessA.restype = BOOL

# debugging and thread_hijack
# DebugActiveProcess(hProcess)
__DebugActiveProcess = kernel32.DebugActiveProcess
__DebugActiveProcess.argtypes = [DWORD]
__DebugActiveProcess.restype = BOOL

# DebugActiveProcessStop(hProcess)
__DebugActiveProcessStop = kernel32.DebugActiveProcessStop
__DebugActiveProcessStop.argtypes = [DWORD]
__DebugActiveProcessStop.restype = BOOL

# DebugBreakProcess(hProcess)
__DebugBreakProcess = kernel32.DebugBreakProcess
__DebugBreakProcess.argtypes = [HANDLE]
__DebugBreakProcess.restype = BOOL

# DebugSetProcessKillOnExit(KillOnExit)
DebugSetProcessKillOnExit = kernel32.DebugSetProcessKillOnExit
DebugSetProcessKillOnExit.argtypes = [BOOL]
DebugSetProcessKillOnExit.restype = BOOL

# ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus );
__ContinueDebugEvent = kernel32.ContinueDebugEvent
__ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
__ContinueDebugEvent.restype = BOOL

# WaitForDebugEvent(lpDebugEvent, dwMilliseconds );
__WaitForDebugEvent = kernel32.WaitForDebugEvent
__WaitForDebugEvent.argtypes = [POINTER(DEBUG_EVENT), DWORD]
__WaitForDebugEvent.restype = BOOL

# GetThreadContext(hThread, lpContext)
__GetThreadContext = kernel32.GetThreadContext
__GetThreadContext.argtypes = [DWORD, POINTER(CONTEXT64)]
__GetThreadContext.restype = BOOL

# SetThreadContext(hThread, lpContext)
__SetThreadContext = kernel32.SetThreadContext
__SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
__SetThreadContext.restype = BOOL

# Wow64GetThreadContext(hThread, lpContext)
__Wow64GetThreadContext = kernel32.Wow64GetThreadContext
__Wow64GetThreadContext.argtypes = [DWORD, POINTER(CONTEXT32)]
__Wow64GetThreadContext.restype = BOOL

# Wow64SetThreadContext(hThread, lpContext)
__Wow64SetThreadContext = kernel32.Wow64SetThreadContext
__Wow64SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT32)]

# FlushInstructionCache(hProcess, lpBaseAddress, dwSize );
__FlushInstructionCache = kernel32.FlushInstructionCache
__FlushInstructionCache.argtypes = [HANDLE, LPCVOID, c_size_t]
__FlushInstructionCache.restype = BOOL

# CreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut,
# lpSecurityAttributes );
__CreateNamedPipeA = kernel32.CreateNamedPipeA
__CreateNamedPipeA.argtypes = [LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, POINTER(SECURITY_ATTRIBUTES)]
__CreateNamedPipeA.restype = HANDLE

# PeekNamedPipe(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage );
__PeekNamedPipe = kernel32.PeekNamedPipe
__PeekNamedPipe.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD]
__PeekNamedPipe.restype = BOOL

# external api


def GetSystemInfo():
    system_info = SYSTEM_INFO()
    __GetSystemInfo(byref(system_info))
    return system_info


def GetModuleHandle(module):
    c_data = c_char_p(bytes(module, "ASCII"))
    handle = __GetModuleHandle(c_data)
    if handle == winerror.ERROR_INVALID_HANDLE:
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
    if handle == winerror.ERROR_INVALID_HANDLE:
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
        winnt.PROCESS_ALL_ACCESS, b_inherit_handle, pid)

    if process_handle == 0:
        report_last_error()
    return process_handle


def OpenThread(tid, b_inherit_handle=False):
    thread_handle = __OpenThread(
        winnt.THREAD_ALL_ACCESS, b_inherit_handle, tid)
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
                   allocation_type=winnt.MEM_COMMIT,
                   protect=winnt.PAGE_EXECUTE_READWRITE):
    new_memory = __VirtualAllocEx(
        process_handle, address, size, allocation_type, protect)
    if not new_memory:
        report_last_error()
    else:
        return new_memory


def VirtualFreeEx(process_handle, address,
                  size=0, free_type=winnt.MEM_RELEASE):
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
    if handle == winerror.ERROR_INVALID_HANDLE:
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
    if result == winnt.WAIT_FAILED:
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
        thread_context.ContextFlags = winnt.CONTEXT_FULL | winnt.CONTEXT_DEBUG_REGISTERS
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


def FlushInstructionCache(process_handle, address, size):
    success = __FlushInstructionCache(process_handle, address, size)
    if not success:
        report_last_error()
    return success
