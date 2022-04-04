from . import kernel32
from . import ntdll
from . import winnt
from . import winerror
from .x86 import Dsm, Asm
import pefile
import struct
import ctypes
import time
from typing import Union, Generator, Any

# by default load the entire PE file
pefile.fast_load = False

# suspend the process when injecting code
global_use_suspend_process = True


class Process(object):
    def __init__(self, process):
        """
        To see if attaching was successful check Process.failed : bool
        @param process: can either be a process id or a process name (gets the first match)
        """
        if type(process) == int:
            self.process_id = process
            self.handle = kernel32.OpenProcess(self.process_id)
            if self.handle != winerror.ERROR_INVALID_HANDLE:
                self.failed = False
            else:
                self.failed = True
        if type(process) == str:
            proc = get_process_first(process)
            if proc is not None:
                self.process_id = proc.pid
                self.handle = kernel32.OpenProcess(self.process_id)
                self.failed = False
            else:
                self.failed = True
        self.mode = self.is_32bit()
        self.patches = {}
        self.hooks = {}
        self.vt_hooks = {}
        self.injected_threads = []
        self.asm = Asm(self.mode)
        self.dsm = Dsm(self.mode)

    def __del__(self):
        if 'handle' in dir(self):
            kernel32.CloseHandle(self.handle)

    def is_alive(self) -> bool:
        """
        @return bool - if the process is running it will return True:
        """
        alive = kernel32.WaitForSingleObject(self.handle, 0)
        if alive == winnt.WAIT_TIMEOUT:
            return True
        else:
            return False

    def kill(self, exit_code: int) -> bool:
        """
        Kills the target process
        @param exit_code: exit code reason for termination
        @return bool - if process was terminated return True:
        """
        return kernel32.TerminateProcess(self.handle, exit_code)

    def is_32bit(self) -> bool:
        """
        Checks whether target process is running under 32bit mode or 64bit mode
        To elaborate, it checks whether its running under Wow64.
        @return bool - returns True if 32bit, otherwise its 64bit
        """
        return kernel32.IsWow64Process(self.handle)

    def address(self, address: int, c_type):
        """
        Creates an Address object using the
        process handle from this process object.

        @param address: address of the value
        @param c_type: the ctype of the value
        @return Address:

        """
        return Address(self, address, c_type)

    def pointer(self, base_address: int, offsets: list, c_type):
        """
        Creates a Pointer object using the
        process handle from this process object.

        @param base_address: base address of pointer
        @param offsets: a list of offsets to get to the final address
        @param c_type: the ctype of the value being pointed to
        @return: badtooth.Pointer

        """
        return Pointer(self, base_address, offsets, c_type)

    def read(self, address: int, n_bytes: int) -> bytearray:
        """
        If the badtooth api fails it can partially fail and return less bytes than intended.
        Will fail if memory range crosses into a PAGE_NOACCESS memory region etc.

        @param address: address to read from
        @param n_bytes: number of bytes to read
        Read specified bytes from the target process
        """
        return kernel32.ReadProcessMemory(self.handle, address, n_bytes)

    def read_memory(self, region: kernel32.MEMORY_BASIC_INFORMATION) -> Union[bytes, bytearray]:
        base, size = region.get_memory_range()
        return self.read(base, size)

    def read_string(self, address: int, max_length=0) -> str:
        """
        Read an ASCII string from target process
        @param address: address of string to read
        @param max_length: maximum string length

        """
        string = ""
        i = 0
        while True:
            if max_length and max_length == i:
                return string
            char = self.read(address + i, 1)[0]
            if 0x20 <= char < 0x7f:
                string = string + chr(char)
                i = i + 1
            elif char == 0:
                return string
            else:
                return ""

    def read_structure(self, address: int, structure: ctypes.Structure):
        """
        Read a structure from process into a local ctypes instance
        """
        data = bytes(kernel32.ReadProcessMemory(self.handle, address, ctypes.sizeof(structure)))
        data = ctypes.c_buffer(data)
        fit = min(len(data), ctypes.sizeof(structure))
        ctypes.memmove(ctypes.addressof(structure), data, fit)

    def write(self, address: int, buffer: Union[bytes, bytearray]) -> bool:
        """
        Write a buffer to the target process at the specified address

        Process.write(address, buffer) -> success: bool

        address is the address in the process memory to write to
        buffer is the bytes you want to write to the process
        """
        return kernel32.WriteProcessMemory(self.handle, address, buffer)

    def write_structure(self, address: int, structure):
        """
        Writes a local ctypes structure instance to process memory
        """
        data = bytes(structure)
        kernel32.WriteProcessMemory(self.handle, address, data)

    def protect(self, address: int, size: int, protection: int) -> bool:
        """
        Sets the memory protection of page(s)
        """
        return kernel32.VirtualProtectEx(self.handle, address, size, protection)

    def alloc_rwx(self, size: int) -> int:
        """
        Allocate memory to the target process
        Memory has read/write/execute permissions

        Process.alloc_rwx(size) -> address: int

        """
        return kernel32.VirtualAllocEx(self.handle, 0, size)

    def alloc_rw(self, size: int) -> int:
        """
        Allocate memory to the target process
        Memory has read/write permissions

        Process.alloc_rwx(size) -> address: int
        """
        return kernel32.VirtualAllocEx(self.handle, 0, size,
                                       protect=winnt.PAGE_READWRITE)

    def free(self, address: int) -> bool:
        """
        @param
        Releases committed memory from the target process
        """
        return kernel32.VirtualFreeEx(self.handle, address)

    def get_threads(self) -> list:
        """Enumerate all threads in process
        and returns a list"""
        threads = []
        h_snapshot = kernel32.CreateToolhelp32Snapshot(
            winnt.TH32CS_SNAPTHREAD, 0)
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

    def yield_modules(self) -> iter:
        """
        Yields modules one by one using a generator object
        Each module is a MODULEENTRY32 structure object
        Modules belong to the target process

        Process.yield_modules() -> Generator(kernel32.MODULEENTRY32)

        Only works if process is the same bits (32/64) as python instance!
        """
        h_snapshot = kernel32.CreateToolhelp32Snapshot(
            winnt.TH32CS_SNAPMODULE, self.process_id)
        module_entry = kernel32.Module32First(h_snapshot)
        yield module_entry
        while kernel32.Module32Next(h_snapshot, module_entry):
            yield module_entry

    def get_module(self, module_name: str) -> kernel32.MODULEENTRY32:
        """
        @param module_name: the name of the module to get info on
        Gets the MODULE_ENTRY_32 struct for
        a specific module in the process
        Only works if process is the same bits (32/64) as python instance!
        """
        module_name = module_name.lower()
        module_gen = self.yield_modules()
        for module_entry in module_gen:
            curr_module_name = module_entry.name.lower()
            if curr_module_name.find(module_name) != -1:
                return module_entry

    def get_pe_info(self, module_name: str) -> pefile.PE:
        """
        @param module_name: the name of the module to get pe info from
        Returns a PE object (pefile module) for a module
        in the process
        Grabs the data from file
        """
        module = self.get_module(module_name)
        pe = pefile.PE(module.path)
        return pe

    def get_pe_info_memory(self, module_name: str) -> pefile.PE:
        """
        @param module_name: the name of the module to get pe info from
        Returns a PE object (pefile module) for a module
        in the process
        Grabs the data from memory
        """
        module = self.get_module(module_name)
        data = self.read(module.base_address, module.size)
        return pefile.PE(data=data)

    def get_exports(self, module_name: str):
        """
        @param module_name: the name of the module to get exports from
        Get all exports for specified module name in the process
        """
        export_dict = {}
        module = self.get_module(module_name)
        pe = pefile.PE(module.path)
        pe.parse_data_directories()
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_address = export.address + module.base_address
                if export.name:
                    export_dict[export.name.decode("ASCII")] = export_address
                else:
                    export_dict[export.ordinal] = export_address
            return export_dict

    def get_imports(self, module_name: str):
        """
        @param module_name: the name of the module to get imports from
        Get all imports for specified module name in the process
        """
        import_list = []
        module = self.get_module(module_name)
        pe = pefile.PE(module.path)
        pe.parse_data_directories()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_import_list = {}
                dll_name = dll_entry.dll.decode("ASCII")
                base_address = self.get_module(dll_name).base_address
                for import_entry in dll_entry.imports:
                    dll_import_list[import_entry.name] = import_entry.address + base_address
                import_list.append((dll_name, dll_import_list))
            return import_list

    def yield_memory_regions(self, min_address: int = None, max_address: int = None, state: int = None,
                             protect: int = None, m_type: int = None) -> \
            Generator[kernel32.MEMORY_BASIC_INFORMATION, Any, None]:
        """
        Yields memory regions one by one using a generator object
        Each region is a MEMORY_BASIC_INFORMATION structure object
        Regions belong to the target process

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

    def create_thread(self, address, parameter=0) -> int:
        """
        @param address: address to start the new thread at
        @param parameter: optional integer parameter for the new thread
        Creates a thread in the target process at specified address, default parameter is NULL
        Parameter can be a pointer to some variable for the code that is executed to use.
        """
        thread = kernel32.CreateRemoteThreadEx(self.handle, address, parameter)
        self.injected_threads.append(thread)
        return thread

    def created_threads_done(self) -> bool:
        """
        Checks if all injected threads have finished executing.
        Removes completed threads from the list
        Returns true if all injected threads have finished executing.
        """
        threads_done = True
        for thread in self.injected_threads:
            event = kernel32.WaitForSingleObject(thread, 0)
            if event == winnt.WAIT_TIMEOUT:
                threads_done = False
            else:
                self.injected_threads.remove(thread)
        return threads_done

    def flush_instr_cache(self, address: int, size: int):
        """Flushes the CPU instruction cache at specified location"""
        return kernel32.FlushInstructionCache(self.handle, address, size)

    def add_patch(self, patch_name: str, address: int, assembly_code: Union[bytes, bytearray]):
        """
        Adds a patch to the patches list, applies patch to the process
        The patch is registered with a dictionary Process.patches
        using the supplied patch_name
        Use Process.toggle_patch(patch_name) to enable or disable the patch

        @param patch_name: name of the patch to create
        @param address: address to patch
        @param assembly_code: raw machine code bytes or a string of instructions separated with ';'

        """
        injected_code = b''
        if type(assembly_code) == str:
            injected_code = self.asm.assemble(assembly_code)
        elif type(assembly_code) == bytes or type(assembly_code) == bytearray:
            injected_code = assembly_code
        old_data = self.read(address, len(injected_code))
        self.write(address, injected_code)
        self.patches[patch_name] = (address, old_data)

    def toggle_patch(self, patch_name: str):
        """
        @param patch_name: name of the installed patch to toggle
        Toggles a patch on or off
        This function swaps the bytes between the original code
        and the new code (instructions argument in Process.add_patch)
        """
        patch_address, old_data = self.patches[patch_name]
        patch_size = len(old_data)
        patch_instructions = self.read(patch_address, patch_size)
        old_protect = self.protect(patch_address, patch_size, winnt.PAGE_EXECUTE_READWRITE)
        self.write(patch_address, old_data)
        self.protect(patch_address, patch_size, old_protect)
        self.flush_instr_cache(patch_address, patch_size)
        self.patches[patch_name] = (patch_address, patch_instructions)

    # plan to simplify the hook engine by stubbing out some of the repeated code and making
    # it into separate functions. e.g. get_instr_len(hook_address, max, read_size)

    def detour_hook(self, target_address: int, hook_address: int):
        """
        Used internally, injects a jump into the hook_address code that
        jumps into target_address
        """
        if self.mode:
            instr_data = self.read(hook_address, 30)
            instr_length = self.dsm.get_instr_length(instr_data, hook_address, 5)
            nop_instr = b'\x90' * (instr_length - 5)
            old_protect = self.protect(hook_address, instr_length, winnt.PAGE_EXECUTE_READWRITE)
            hook_relative = target_address - hook_address - 5
            hook_inject = b'\xE9' + struct.pack("i", hook_relative) + nop_instr
        else:
            instr_data = self.read(hook_address, 30)
            instr_length = self.dsm.get_instr_length(instr_data, hook_address, 14)
            nop_instr = b'\x90' * (instr_length - 14)
            old_protect = self.protect(hook_address, instr_length, winnt.PAGE_EXECUTE_READWRITE)
            hook_inject = b'\xFF\x25\x00\x00\x00\x00' + \
                          struct.pack("Q", target_address) + nop_instr
        old_bytes = self.read(hook_address, instr_length)
        if global_use_suspend_process:
            self.suspend()
        self.write(hook_address, hook_inject)
        self.flush_instr_cache(hook_address, instr_length)
        self.protect(hook_address, instr_length, old_protect)
        if global_use_suspend_process:
            self.resume()
        return old_bytes

    def add_hook(self, hook_name: str, hook_address: int, assembly_code: Union[str, bytes]):
        """
        @param hook_name: name of the hook to be created
        @param hook_address: address to install the hook on
        @param assembly_code: raw machine code bytes or a string of instructions separated with ';'
        Adds a hook to the process, which is registered to the list with hook_name
        """
        injected_code = b''
        if type(assembly_code) == str:
            injected_code = self.asm.assemble(assembly_code)
        elif type(assembly_code) == bytes or type(assembly_code) == bytearray:
            injected_code = assembly_code
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
        self.hooks[hook_name] = (hook_address, old_bytes, target_address, True)

    def toggle_hook(self, hook_name: str):
        """
        @param hook_name: name of the installed hook to toggle
        Toggles a hook on or off
        Does not free the allocated memory for the injected code
        """
        hook_address, old_bytes, target_address, enabled = self.hooks[hook_name]
        hook_size = len(old_bytes)
        hook_instructions = self.read(hook_address, hook_size)
        if global_use_suspend_process:
            self.suspend()
        old_protect = self.protect(hook_address, hook_size, winnt.PAGE_EXECUTE_READWRITE)
        self.write(hook_address, old_bytes)
        self.flush_instr_cache(hook_address, hook_size)
        self.protect(hook_address, hook_size, old_protect)
        if global_use_suspend_process:
            self.resume()
        self.hooks[hook_name] = (hook_address, hook_instructions, target_address, not enabled)

    def remove_hook(self, hook_name: str):
        """
        @param hook_name: name of the installed hook to remove
        Disables a hook and removes it from the list
        Frees the allocated memory for the injected code
        """
        hook_address, old_bytes, target_address, enabled = self.hooks[hook_name]
        if enabled:
            self.toggle_hook(hook_name)
        self.free(target_address)
        self.hooks.pop(hook_name)

    def add_vt_hook(self, hook_name: str, p_virtual_table: int, index: int, assembly_code: Union[str, bytes]):
        """
        Adds a virtual function table hook to the process
        @param hook_name: name of the hook
        @param p_virtual_table: pointer to the virtual function table
        @param index: index into the table to hook (first func is 0, 2nd is 1...)
        @param assembly_code: code or bytes to inject
        """
        injected_code = b''
        if type(assembly_code) == str:
            injected_code = self.asm.assemble(assembly_code)
        elif type(assembly_code) == bytes or type(assembly_code) == bytearray:
            injected_code = assembly_code
        target_address = self.alloc_rwx(len(injected_code))
        self.write(target_address, injected_code)
        if self.mode:
            ct = ctypes.c_uint32
        else:
            ct = ctypes.c_uint64
        fptr = self.address(p_virtual_table + (index * ctypes.sizeof(ct)), ct)
        old_protect = self.protect(p_virtual_table, 512, winnt.PAGE_READWRITE)
        original_function = fptr.read()
        fptr.write(target_address)
        self.protect(p_virtual_table, 512, old_protect)
        self.vt_hooks[hook_name] = (fptr, original_function, target_address, True)

    def toggle_vt_hook(self, hook_name):
        """
        @param hook_name: name of the installed virtual function hook to toggle
        Toggles a hook on or off
        Does not free the allocated memory for the injected code
        """
        fptr, original_function, target_address, enabled = self.vt_hooks[hook_name]
        old_protect = self.protect(fptr.address, 512, winnt.PAGE_READWRITE)
        if enabled:
            fptr.write(original_function.value)
        else:
            fptr.write(target_address)
        self.protect(fptr.address, 512, old_protect)
        self.vt_hooks[hook_name] = (fptr, original_function, target_address, not enabled)

    def remove_vt_hook(self, hook_name):
        """
        @param hook_name: name of the installed hook to remove
        Disables a virtual function hook and removes it from the list
        Frees the allocated memory for the injected code
        """
        fptr, original_function, target_address, enabled = self.vt_hooks[hook_name]
        old_protect = self.protect(fptr.address, 512, winnt.PAGE_READWRITE)
        fptr.write(original_function.value)
        self.protect(fptr.address, 512, old_protect)
        self.free(target_address)
        self.vt_hooks.pop(hook_name)

    def inject_dll(self, dll_path: str):
        """
        Injects a dll into the process
        This function uses LoadLibraryA and CreateRemoteThreadEx
        which is very loud. Will not work against most anti-cheats
        """
        kernel32_handle = kernel32.GetModuleHandle("kernel32.dll")
        load_lib = kernel32.GetProcAddress(kernel32_handle, "LoadLibraryA")
        path_internal = self.alloc_rw(len(dll_path))
        self.write(path_internal, bytes(dll_path, "ASCII"))
        self.create_thread(load_lib, parameter=path_internal)


class ProcessWatcher(object):
    def __init__(self, process: Process):
        self.process = process
        self.proc = None
        self.attached = False

    def wait_for(self) -> Process:
        """Wait for the process to start running"""
        proc = Process(self.process)
        while proc.failed:
            proc = Process(self.process)
        self.proc = proc
        self.attached = True
        return proc

    def is_alive(self) -> bool:
        """Check if process is still running"""
        return self.proc.is_alive()

    def wait_for_suspend(self):
        """Wait for the process to start and immediately suspend it"""
        self.wait_for()
        self.proc.suspend()

    def resume(self):
        """
        Resume the process under watch
        """
        self.proc.resume()

    def watch_address(self, address: int, size: int) -> bool:
        """
        Sleeps the thread until memory region data changes
        Useful for unpacker writing maybe?
        """
        original_bytes = self.proc.read(address, size)
        changed = False
        while not changed:
            time.sleep(0.05)
            curr_bytes = self.proc.read(address, size)
            if curr_bytes != original_bytes:
                changed = True
        return True


class Address(object):
    """
    class Address(object)
     | Address(process, address, c_type) -> Address
     |
     |
    """

    def __init__(self, process: Process, address: int, c_type):
        if not process.failed and process.is_alive():
            self.handle = process.handle
            self.address = address
            self.size = ctypes.sizeof(c_type)
            self.c_type = c_type

    def read(self):
        """
        Read a value from this address
        """
        data = bytes(kernel32.ReadProcessMemory(self.handle, self.address, self.size))
        if data is None:
            return None
        if len(data) == self.size:
            data = ctypes.c_buffer(data)
            return ctypes.cast(data, ctypes.POINTER(self.c_type)).contents
        return None

    def read_offset(self, offset: int):
        """
        Read a value from this address + offset
        """
        data = kernel32.ReadProcessMemory(self.handle, self.address + offset, self.size)
        if data is None:
            return None
        if len(data) == self.size:
            return ctypes.cast(data, ctypes.POINTER(self.c_type)).contents
        return None

    def write(self, value: Union[int, float, tuple]):
        """
        Write a value to this address
        In the case of an array use a tuple of that array (1,2,3)...
        """
        data = bytes(self.c_type(value))
        return kernel32.WriteProcessMemory(self.handle, self.address, data)


class Pointer(Address):
    """
    class Pointer(Address)
     | Pointer(process, base_address, offsets, c_type) -> Address
     |
     |
    """

    def __init__(self, process: Process, base_address: int, offsets: list, c_type):
        if not process.failed and process.is_alive():
            super(Pointer, self).__init__(process, 0, c_type)
            self.pointer_size = 4 if process.mode else 8
            self.c_pointer = ctypes.POINTER(ctypes.c_uint32) if process.mode else ctypes.POINTER(ctypes.c_uint64)
            self.base_address = base_address
            self.address = 0
            self.offsets = offsets
            self.resolve()

    def resolve(self) -> bool:
        """
        Updates the local pointer to the address of the remote memory
        """
        address = self.base_address
        for offset in self.offsets:
            data = bytes(kernel32.ReadProcessMemory(self.handle, address, self.pointer_size))
            if data is None:
                return False
            data = ctypes.c_buffer(data)
            address = ctypes.cast(data, self.c_pointer)[0]
            address += offset
        self.address = address
        return True


def start(app_name: str, command_line: str) -> Process:
    """Start a process"""
    process_id = kernel32.CreateProcess(app_name, command_line, 0)
    return Process(process_id)


def start_suspended(app_name: str, command_line: str) -> Process:
    """Start a process in suspended state"""
    process_id = kernel32.CreateProcess(app_name, command_line, winnt.CREATE_SUSPENDED)
    return Process(process_id)


def yield_processes() -> iter:
    """Get all running processes via snapshot, returns generator object"""
    h_snapshot = kernel32.CreateToolhelp32Snapshot(
        winnt.TH32CS_SNAPPROCESS, 0)
    proc_entry = kernel32.Process32First(h_snapshot)
    yield proc_entry
    while kernel32.Process32Next(h_snapshot, proc_entry):
        yield proc_entry


def get_process_first(process_name: str) -> kernel32.PROCESSENTRY32:
    """Returns the first process in the list that matches with the input string"""
    for process in yield_processes():
        curr_process_name = process.name.lower()
        if curr_process_name.find(process_name.lower()) != -1:
            return process


def get_processes(process_name: str) -> list:
    """returns a list of running processes that match the input string"""
    process_list = []
    process_name = process_name.lower()
    h_snapshot = kernel32.CreateToolhelp32Snapshot(
        winnt.TH32CS_SNAPPROCESS, 0)
    proc_entry = kernel32.Process32First(h_snapshot)
    while kernel32.Process32Next(h_snapshot, proc_entry):
        name = proc_entry.name.lower()
        if name.find(process_name) != -1:
            process_list.append((name, proc_entry.pid))
    return process_list


def enable_se_debug():
    """Enable debug privileges - warning! malicious scripts can abuse this
    SE_DEBUG_PRIVILEGE allows this process to get handles to any process under any user
    can only change the token when running under administrative rights"""
    ntdll.AdjustPrivilege(
        ntdll.SE_DEBUG_PRIVILEGE, True)
