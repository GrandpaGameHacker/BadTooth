import windows_api.kernel32
import windows_api.ntdll
import windows_api.winnt_constants


def yield_processes():
    hSnapshot = windows_api.kernel32.CreateToolhelp32Snapshot(
        windows_api.winnt_constants.TH32CS_SNAPPROCESS, 0)
    proc_entry = windows_api.kernel32.Process32First(hSnapshot)
    yield proc_entry
    while windows_api.kernel32.Process32Next(hSnapshot, proc_entry):
        yield proc_entry


def get_process_first(process_name):
    for process in yield_processes():
        curr_process_name = process.get_name()
        if curr_process_name == process_name:
            return process


def get_processes(process_name):
    process_list = []
    for process in yield_processes():
        curr_process_name = process.get_name()
        if curr_process_name == process_name:
            process_list.append(process)
    return process_list


def enable_sedebug():
    windows_api.ntdll.AdjustPrivilege(
        windows_api.ntdll.SE_DEBUG_PRIVILEGE, True)


class Process(object):
    def __init__(self, process_id):
        self.handle = windows_api.kernel32.OpenProcess(process_id)

    def __del__(self):
        windows_api.kernel32.CloseHandle(self.handle)

    def read(self, address, n_bytes):
        return windows_api.kernel32.ReadProcessMemory(self.handle, address, n_bytes)

    def write(self, address, buffer):
        return windows_api.kernel32.WriteProcessMemory(self.handle, address, buffer)

    def alloc_rwx(self, size):
        return windows_api.kernel32.VirtualAllocEx(self.handle, 0, size)

    def alloc_rw(self, size):
        protect = windows_api.kernel32.PAGE_READWRITE
        return windows_api.kernel32.VirtualAllocEx(self.handle, 0, size, protect)

    def free(self, address):
        return windows_api.kernel32.VirtualFreeEx(self.handle, address)

    def yield_memory_regions(self):
        system_info = windows_api.kernel32.GetSystemInfo()
        min_address = system_info.lpMinimumApplicationAddress
        mem_basic_info = windows_api.kernel32.VirtualQueryEx(self.handle, min_address)

    def create_thread(self, address, parameter=0):
        return windows_api.kernel32.CreateRemoteThreadEx(self.handle, address, parameter)
