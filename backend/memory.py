from . import kernel32
from . import ntdll
from . import winnt_constants


class Process(object):
    def __init__(self, process_id):
        self.handle = kernel32.OpenProcess(process_id)
        self.patches = {}

    def __del__(self):
        kernel32.CloseHandle(self.handle)

    def read(self, address, n_bytes):
        return kernel32.ReadProcessMemory(self.handle, address, n_bytes)

    def write(self, address, buffer):
        return kernel32.WriteProcessMemory(self.handle, address, buffer)

    def alloc_rwx(self, size):
        return kernel32.VirtualAllocEx(self.handle, 0, size)

    def alloc_rw(self, size):
        return kernel32.VirtualAllocEx(self.handle, 0, size,
                                       protect=kernel32.PAGE_READWRITE)

    def free(self, address):
        return kernel32.VirtualFreeEx(self.handle, address)

    def yield_memory_regions(self, state=None, protect=None, m_type=None):
        system_info = kernel32.GetSystemInfo()
        min_address = system_info.lpMinimumApplicationAddress
        max_address = system_info.lpMaximumApplicationAddress
        mem_basic_info = kernel32.VirtualQueryEx(
            self.handle, min_address)

        while mem_basic_info is not None:
            bState = True
            bProtect = True
            bType = True
            if state:
                bState = mem_basic_info.State == state
            if protect:
                bProtect = mem_basic_info.Protect == protect
            if m_type:
                bType = mem_basic_info.Type == m_type
            if bState and bProtect and bType:
                yield mem_basic_info
            address = mem_basic_info.BaseAddress + mem_basic_info.RegionSize
            if address > max_address:
                break
            mem_basic_info = kernel32.VirtualQueryEx(
                self.handle, address)

    def create_thread(self, address, parameter=0):
        return kernel32.CreateRemoteThreadEx(self.handle, address, parameter)

    def add_patch(self, patch_name, address, data):
        old_data = self.read(address, len(data))
        self.write(address, data)
        self.patches[patch_name] = (address, old_data)

    def toggle_patch(self, patch_name):
        address_i = 0
        data_i = 1
        patch_size = len(self.patches[patch_name][data_i])
        patch_address = self.patches[patch_name][address_i]
        patch_data = self.read(patch_address, patch_size)
        self.write(patch_address, self.patches[patch_name][data_i])
        self.patches[patch_name] = (patch_address, patch_data)


def yield_processes():
    hSnapshot = kernel32.CreateToolhelp32Snapshot(
        winnt_constants.TH32CS_SNAPPROCESS, 0)
    proc_entry = kernel32.Process32First(hSnapshot)
    yield proc_entry
    while kernel32.Process32Next(hSnapshot, proc_entry):
        yield proc_entry


def get_process_first(process_name):
    for process in yield_processes():
        curr_process_name = process.get_name()
        if curr_process_name.find(process_name) != -1:
            return process


def get_processes(process_name):
    process_list = []
    for process in yield_processes():
        curr_process_name = process.get_name()
        if curr_process_name.find(process_name) != -1:
            process_list.append(process)
    return process_list


def enable_sedebug():
    ntdll.AdjustPrivilege(
        ntdll.SE_DEBUG_PRIVILEGE, True)
