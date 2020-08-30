from . import kernel32
from . import ntdll
from . import winnt_constants

import struct


class Process(object):
    def __init__(self, process_id):
        self.process_id = process_id
        self.handle = kernel32.OpenProcess(process_id)
        self.patches = {}
        self.hooks = {}

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

    def yield_threads(self):
        hSnapshot = kernel32.CreateToolhelp32Snapshot(
            winnt_constants.TH32CS_SNAPTHREAD, 0)
        thread_entry = kernel32.Thread32First(hSnapshot)
        yield thread_entry
        while kernel32.Thread32Next(hSnapshot, thread_entry):
            yield thread_entry

    def suspend(self):
        for thread in self.yield_threads():
            if thread.get_owner_pid() == self.process_id:
                thread_handle = kernel32.OpenThread(thread.get_tid())
                kernel32.SuspendThread(thread_handle)
                kernel32.CloseHandle(thread_handle)

    def resume(self):
        for thread in self.yield_threads():
            if thread.get_owner_pid() == self.process_id:
                thread_handle = kernel32.OpenThread(thread.get_tid())
                kernel32.ResumeThread(thread_handle)
                kernel32.CloseHandle(thread_handle)

    def yield_modules(self):
        hSnapshot = kernel32.CreateToolhelp32Snapshot(winnt_constants.TH32CS_SNAPMODULE, self.process_id)
        module_entry = kernel32.Module32First(hSnapshot)
        yield module_entry
        while kernel32.Module32Next(hSnapshot, module_entry):
            yield module_entry

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

    def add_patch(self, patch_name, address, instructions):
        old_data = self.read(address, len(instructions))
        self.write(address, instructions)
        self.patches[patch_name] = (address, old_data)

    def toggle_patch(self, patch_name):
        address_i = 0
        instructions_i = 1
        patch_size = len(self.patches[patch_name][instructions_i])
        patch_address = self.patches[patch_name][address_i]
        patch_instructions = self.read(patch_address, patch_size)
        self.write(patch_address, self.patches[patch_name][instructions_i])
        self.patches[patch_name] = (patch_address, patch_instructions)

    def detour_hook(self, target_address, hook_address, instr_length):
        if is_process_32bit(self.handle):
            nops = b''
            if instr_length > 5:
                nops = b'\x90' * (instr_length - 5)
            old_protect = kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, kernel32.PAGE_EXECUTE_READWRITE)
            hook_relative = target_address - hook_address - 5
            hook = b'\xE9' + struct.pack("i", hook_relative) + nops
            old_bytes = self.read(hook_address, instr_length)
            self.write(hook_address, hook)
            kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, old_protect)
            return old_bytes
        else:
            nops = b''
            if instr_length > 14:
                nops = b'\x90' * (instr_length - 14)
            old_protect = kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, kernel32.PAGE_EXECUTE_READWRITE)
            hook = b'\xFF\x25\x00\x00\x00\x00' + \
                struct.pack("Q", target_address) + nops
            old_bytes = self.read(hook_address, instr_length)
            self.write(hook_address, hook)
            kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, old_protect)
            return old_bytes

    def add_hook(self, hook_name, hook_address, hook_instr_len, new_code):
        self.suspend()
        target_address = self.alloc_rwx(len(new_code))
        if is_process_32bit(self.handle):
            hook_relative = hook_address - (target_address + len(new_code))
            new_code = new_code + b'\xE9' + struct.pack("i", hook_relative)
        else:
            new_code = new_code + b'\xFF\x25\x00\x00\x00\x00' + \
                struct.pack("Q", hook_address + hook_instr_len)
        self.write(target_address, new_code)
        old_bytes = self.detour_hook(
            target_address, hook_address, hook_instr_len)
        self.resume()
        self.hooks[hook_name] = (hook_address, old_bytes, target_address)

    def remove_hook(self, hook_name):
        hook_address, old_bytes, target_address = self.hooks[hook_name]
        self.suspend()
        self.write(hook_address, old_bytes)
        self.free(target_address)
        self.resume()
        self.hooks.pop(hook_name)


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


def is_process_32bit(handle):
    return kernel32.IsWow64Process(handle)
