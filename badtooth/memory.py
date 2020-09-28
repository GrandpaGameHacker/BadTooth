from . import kernel32
from . import ntdll
from . import winnt_constants
from .x86 import Dsm, Asm
import pefile
import struct
import time

pefile.fast_load = False


def start(app_name, command_line):
    process_id = kernel32.CreateProcess(app_name, command_line, 0)
    return Process(process_id)


def start_suspended(app_name, command_line):
    process_id = kernel32.CreateProcess(app_name, command_line, winnt_constants.CREATE_SUSPENDED)
    return Process(process_id)


def yield_processes():
    h_snapshot = kernel32.CreateToolhelp32Snapshot(
        winnt_constants.TH32CS_SNAPPROCESS, 0)
    proc_entry = kernel32.Process32First(h_snapshot)
    yield proc_entry
    while kernel32.Process32Next(h_snapshot, proc_entry):
        yield proc_entry


def get_process_first(process_name):
    for process in yield_processes():
        curr_process_name = process.name.lower()
        if curr_process_name.find(process_name.lower()) != -1:
            return process


def get_processes(process_name):
    process_list = []
    for process in yield_processes():
        curr_process_name = process.name.lower()
        if curr_process_name.find(process_name.lower()) != -1:
            process_list.append(process)
    return process_list


def enable_se_debug():
    ntdll.AdjustPrivilege(
        ntdll.SE_DEBUG_PRIVILEGE, True)


class Process(object):
    """
    class Process(object)
     | Process(process_id) -> Process
     | 
     | Create a new process object which opens a handle
     | to the process specified by process_id
     | Process will automatically close the handle upon destruction.
    """

    def __init__(self, process):
        """
        Process(process) -> Process
        process can either be a process id or a process name (gets first entry)
        internal variables:
        process_id - ID of target process
        handle - handle to target process
        patches - dictionary of all loaded patches
        hooks - dictionary of all loaded hooks
        """
        if type(process) == int:
            self.process_id = process
            self.handle = kernel32.OpenProcess(self.process_id)
        if type(process) == str:
            proc = get_process_first(process)
            if proc is not None:
                self.process_id = proc.pid
                self.handle = kernel32.OpenProcess(self.process_id)
                self.failed = False
            else:
                self.failed = True
                return
        self.mode = self.is_32bit()
        self.patches = {}
        self.hooks = {}
        self.injected_threads = []
        self.asm = Asm(self.mode)
        self.dsm = Dsm(self.mode)

    def __del__(self):
        """
        Calls Kernel32.dll->CloseHandle(self.handle) upon destruction
        """
        if 'handle' in dir(self):
            kernel32.CloseHandle(self.handle)

    def is_alive(self):
        alive = kernel32.WaitForSingleObject(self.handle, 0)
        if alive == winnt_constants.WAIT_TIMEOUT:
            return True
        else:
            return False

    def kill(self, exit_code):
        return kernel32.TerminateProcess(self.handle, exit_code)

    def is_32bit(self):
        """
        Checks whether target process is running under 32bit mode or 64bit mode
        To elaborate, it checks whether its running under Wow64.
        Returns True if process is 32bit, false if it is 64bit

        Process.is_32bit() -> result: bool
        """
        return kernel32.IsWow64Process(self.handle)

    def read(self, address, n_bytes):
        """
        Read specified bytes from the target process

        Process.read(address, n_bytes) -> buffer: bytearray

        address is the address in the process memory to read from
        n_bytes is the number of bytes to be read
        If the badtooth api fails it can partially fail and return less bytes than intended.
        Will fail if memory range crosses into a PAGE_NOACCESS memory region etc.
        """
        return kernel32.ReadProcessMemory(self.handle, address, n_bytes)

    def read_memory(self, region):
        base, size = region.get_memory_range()
        return self.read(base, size)

    def read_string(self, address):
        """
        Read an ASCII string from target process

        Process.read_string(address) -> string: str
        """
        string = ""
        i = 0
        while True:
            char = self.read(address + i, 1)[0]
            if 0x20 <= char < 0x7f:
                string = string + chr(char)
                i = i + 1
            elif char == 0:
                return string

    def write(self, address, buffer):
        """
        Write a buffer to the target process at the specified address

        Process.write(address, buffer) -> success: bool

        address is the address in the process memory to write to
        buffer is the bytes you want to write to the process
        """
        return kernel32.WriteProcessMemory(self.handle, address, buffer)

    def protect(self, address, size, protection):
        return kernel32.VirtualProtectEx(self.handle, address, size, protection)

    def alloc_rwx(self, size):
        """
        Allocate memory to the target process
        Memory has read/write/execute permissions

        Process.alloc_rwx(size) -> address: int

        """
        return kernel32.VirtualAllocEx(self.handle, 0, size)

    def alloc_rw(self, size):
        """
        Allocate memory to the target process
        Memory has read/write permissions

        Process.alloc_rwx(size) -> address: int
        """
        return kernel32.VirtualAllocEx(self.handle, 0, size,
                                       protect=winnt_constants.PAGE_READWRITE)

    def free(self, address):
        """
        Releases committed memory from the target process

        Process.free(address) -> success: bool
        """
        return kernel32.VirtualFreeEx(self.handle, address)

    def get_threads(self):
        threads = []
        h_snapshot = kernel32.CreateToolhelp32Snapshot(
            winnt_constants.TH32CS_SNAPTHREAD, 0)
        thread_entry = kernel32.Thread32First(h_snapshot)
        if thread_entry.owner_pid == self.process_id:
            threads.append(thread_entry)
        while kernel32.Thread32Next(h_snapshot, thread_entry):
            if thread_entry.owner_pid == self.process_id:
                threads.append(thread_entry)
        kernel32.CloseHandle(h_snapshot)
        return threads

    def suspend(self):
        """
        Suspends all running threads in target process

        Process.suspend() -> success: bool
        """
        return ntdll.NtSuspendProcess(self.handle)

    def resume(self):
        """
        Resumes all suspended threads in target process

        Process.suspend() -> success: bool
        """
        return ntdll.NtResumeProcess(self.handle)

    def yield_modules(self):
        """
        Yields modules one by one using a generator object
        Each module is a MODULEENTRY32 structure object
        Modules belong to the target process

        Process.yield_modules() -> Generator(kernel32.MODULEENTRY32)
        """
        h_snapshot = kernel32.CreateToolhelp32Snapshot(
            winnt_constants.TH32CS_SNAPMODULE, self.process_id)
        module_entry = kernel32.Module32First(h_snapshot)
        yield module_entry
        while kernel32.Module32Next(h_snapshot, module_entry):
            yield module_entry

    def get_module_by_name(self, module_name):
        module_name = module_name.lower()
        module_gen = self.yield_modules()
        for module_entry in module_gen:
            curr_module_name = module_entry.name.lower()
            if curr_module_name.find(module_name) != -1:
                return module_entry

    def get_pe_info(self, module_name):
        module = self.get_module_by_name(module_name)
        pe = pefile.PE(module.path)
        return pe

    def get_pe_info_memory(self, module_name):
        module = self.get_module_by_name(module_name)
        data = self.read(module.base_address, module.size)
        return pefile.PE(data=data)

    def get_module_exports(self, module_name):
        export_dict = {}
        module = self.get_module_by_name(module_name)
        pe = pefile.PE(module.path)
        pe.parse_data_directories()
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_address = export.address + module.base_address
            export_dict[export.name.decode("ASCII")] = export_address
        return export_dict

    def get_module_imports(self, module_name):
        import_list = []
        module = self.get_module_by_name(module_name)
        pe = pefile.PE(module.path)
        pe.parse_data_directories()
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_import_list = {}
            dll_name = dll_entry.dll.decode("ASCII")
            base_address = self.get_module_by_name(dll_name).base_address
            for import_entry in dll_entry.imports:
                dll_import_list[import_entry.name] = import_entry.address + base_address
            import_list.append((dll_name, dll_import_list))
        return import_list

    def yield_memory_regions(self, min_address=None, max_address=None, state=None, protect=None, m_type=None):
        """
        Yields memory regions one by one using a generator object
        Each region is a MEMORY_BASIC_INFORMATION structure object
        Regions belong to the target process

        Process.yield_regions(min_address = None, max_address = None, state=None, protect=None, m_type = None) ->
        Generator(kernel32.MEMORY_BASIC_INFORMATION)]

        Each overload (min_address, max_address, state, protect, m_type) allows you to filter for certain
        types of memory, you can have any combination of the five filters.

        min_address and max_address can be used to filter for a range of addresses, for example
        the memory regions inside a module

        state can be -> MEM_COMMIT, MEM_FREE, MEM_RESERVE

        protect can be a number of things, reference here:
        https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
        you can combine them to select multiple types by '|' bitwise or them together

        m_type can be MEM_IMAGE (Regions mapped from exe/dll files), MEM_MAPPED or MEM_PRIVATE

        more information on memory types here:
        https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants

        """
        system_info = kernel32.GetSystemInfo()
        sys_min_address = system_info.lpMinimumApplicationAddress
        sys_max_address = system_info.lpMaximumApplicationAddress
        mem_basic_info = kernel32.VirtualQueryEx(
            self.handle, sys_min_address)

        while mem_basic_info is not None:
            b_min_addr = True
            b_max_addr = True
            b_state = True
            b_protect = True
            b_type = True
            if min_address:
                b_min_addr = mem_basic_info.BaseAddress >= min_address
            if max_address:
                b_max_addr = (mem_basic_info.BaseAddress +
                              mem_basic_info.RegionSize) < max_address
            if state:
                b_state = mem_basic_info.State == state
            if protect:
                b_protect = bool(mem_basic_info.Protect & protect)
            if m_type:
                b_type = mem_basic_info.Type == m_type
            if b_state and b_protect and b_type and b_min_addr and b_max_addr:
                yield mem_basic_info
            address = mem_basic_info.BaseAddress + mem_basic_info.RegionSize
            if max_address:
                if address > max_address:
                    break
            if address > sys_max_address:
                break
            mem_basic_info = kernel32.VirtualQueryEx(
                self.handle, address)

    def create_thread(self, address, parameter=0):
        """
        Creates a thread in the target process at specified address, default parameter is NULL
        Parameter can be a pointer to some variable for the code that is executed to use.

        Process.create_thread(address) -> thread_handle: HANDLE
        Process.create_thread(address, parameter=0) -> thread_handle: HANDLE
        """
        thread = kernel32.CreateRemoteThreadEx(self.handle, address, parameter)
        self.injected_threads.append(thread)

    def created_threads_done(self):
        threads_done = True
        for thread in self.injected_threads:
            event = kernel32.WaitForSingleObject(thread, 0)
            if event == winnt_constants.WAIT_TIMEOUT:
                threads_done = False
            else:
                self.injected_threads.remove(thread)
        return threads_done

    def add_patch(self, patch_name, address, instructions):
        """
        Adds a patch to the patches list, applies patch to the process

        Process.add_patch(patch_name, address, instructions)

        The patch is registered with a dictionary Process.patches
        using the supplied patch_name argument

        The instructions argument is a bytearray of x86/64 assembly code
        that is to be written to the specified address/location in the target code.

        Use Process.toggle_patch(patch_name) to enable or disable the patch
        """
        old_data = self.read(address, len(instructions))
        self.write(address, instructions)
        self.patches[patch_name] = (address, old_data)

    def toggle_patch(self, patch_name):
        """
        Toggles a patch on or off
        This function swaps the bytes between the original code
        and the new code (instructions argument in Process.add_patch)
        """
        address, old_data = self.patches[patch_name]
        patch_size = len(old_data)
        patch_address = address
        patch_instructions = self.read(patch_address, patch_size)
        self.write(patch_address, old_data)
        self.patches[patch_name] = (patch_address, patch_instructions)

    # plan to simplify the hook engine by stubbing out some of the repeated code and making
    # it into separate functions. e.g. get_instr_len(hook_address, max, read_size)

    def detour_hook(self, target_address, hook_address):
        if self.mode:
            instr_data = self.read(hook_address, 30)
            instr_length = self.dsm.get_instr_length(instr_data, hook_address, 5)
            nops = b'\x90' * (instr_length - 5)
            old_protect = kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, winnt_constants.PAGE_EXECUTE_READWRITE)
            hook_relative = target_address - hook_address - 5
            hook_inject = b'\xE9' + struct.pack("i", hook_relative) + nops
            old_bytes = self.read(hook_address, instr_length)
            self.write(hook_address, hook_inject)
            kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, old_protect)
            return old_bytes
        else:
            instr_data = self.read(hook_address, 30)
            instr_length = self.dsm.get_instr_length(instr_data, hook_address, 14)
            nops = b'\x90' * (instr_length - 14)
            old_protect = kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, winnt_constants.PAGE_EXECUTE_READWRITE)
            hook_inject = b'\xFF\x25\x00\x00\x00\x00' + \
                          struct.pack("Q", target_address) + nops
            old_bytes = self.read(hook_address, instr_length)
            self.write(hook_address, hook_inject)
            kernel32.VirtualProtectEx(
                self.handle, hook_address, instr_length, old_protect)
            return old_bytes

    def add_hook(self, hook_name, hook_address, assembly_code):
        injected_code = b''
        if type(assembly_code) == str:
            injected_code = self.asm.assemble(assembly_code)
        elif type(assembly_code) == bytes or type(assembly_code) == bytearray:
            injected_code = assembly_code
        self.suspend()
        target_address = self.alloc_rwx(len(injected_code))
        if self.mode:
            hook_relative = hook_address - (target_address + len(injected_code))
            injected_code += b'\xE9' + struct.pack("i", hook_relative)
        else:
            injected_code += b'\xFF\x25\x00\x00\x00\x00'
            injected_code += struct.pack("Q", hook_address + 14)
        self.write(target_address, injected_code)
        old_bytes = self.detour_hook(
            target_address, hook_address)
        self.resume()
        self.hooks[hook_name] = (hook_address, old_bytes, target_address)

    def remove_hook(self, hook_name):
        hook_address, old_bytes, target_address = self.hooks[hook_name]
        self.suspend()
        self.write(hook_address, old_bytes)
        self.free(target_address)
        self.resume()
        self.hooks.pop(hook_name)

    def inject_dll(self, dll_path):
        kernel32_handle = kernel32.GetModuleHandle("kernel32.dll")
        load_lib = kernel32.GetProcAddress(kernel32_handle, "LoadLibraryA")
        path_internal = self.alloc_rw(len(dll_path))
        self.write(path_internal, bytes(dll_path, "ASCII"))
        self.create_thread(load_lib, parameter=path_internal)


class ProcessWatcher(object):
    def __init__(self, process):
        self.process = process
        self.proc = None
        self.attached = False

    def wait_for(self):
        proc = Process(self.process)
        while proc.failed:
            proc = Process(self.process)
        self.proc = proc
        self.attached = True
        return proc

    def is_alive(self):
        return self.proc.is_alive()

    def wait_for_suspend(self):
        self.wait_for()
        self.proc.suspend()

    def resume(self):
        self.proc.resume()

    def watch_address(self, address, size):
        original_bytes = self.proc.read(address, size)
        changed = False
        while not changed:
            time.sleep(0.05)
            curr_bytes = self.proc.read(address, size)
            if curr_bytes != original_bytes:
                changed = True
        return True
