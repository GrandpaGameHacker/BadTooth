from .backend import *
import struct

class Scanner():
    def __init__(self, process_name):
        self.process_entry = get_process_first(process_name)
        self.process = Process(self.process_entry.get_pid())
        self.process_name = self.process_entry.get_name()
        # scan settings
        self.min_address = 0
        self.max_address = 0x00007fffffffffff
        self.default_protect = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |\
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY
        self.protect = self.default_protect

    def reset_range(self):
        self.min_address = 0
        self.max_address = 0x00007fffffffffff

    def reset_options(self):
        self.reset_range()
        self.protect = self.default_protect

    def find_all(self, base_address, buffer, value):
        matches = []
        b_len = len(buffer)
        v_len = len(value)
        for i in range(b_len):
            for x in range(v_len):
                if buffer[i + x] != value[x]:
                    break
                elif x == v_len - 1:
                    matches.append(base_address + i)
        return matches

    def find_all_aligned(self, base_address, buffer, value):
        matches = []
        b_len = len(buffer)
        v_len = len(value)
        for i in range(b_len, step=v_len):
            for x in range(v_len):
                if buffer[i + x] != value[x]:
                    break
                elif x == v_len - 1:
                    matches.append(base_address + i)
        return matches

    def scan_aob(self, value):
        found = []
        memory_gen = self.process.yield_memory_regions(
            min_address=self.min_address,
            max_address=self.max_address,
            state=MEM_COMMIT, protect=self.protect)

        for memory in memory_gen:
            base, size = memory.get_memory_range()
            if memory.is_readable() is not True:
                continue
            memory_data = self.process.read(base, size)
            if memory_data is not None:
                matches = self.find_all(base, memory_data, value)
                found.extend(matches)
        return found

    def scan_module_aob(self, module, value):
        module_entry = self.process.get_module_by_name(module)
        self.min_address = module_entry.get_base_address()
        self.max_address = module_entry.get_end_address()
        result = self.scan_aob(value)
        self.reset_range()
        return result

    def scan_aob_aligned(self value):
        found = []
        memory_gen = self.process.yield_memory_regions(
            min_address=self.min_address,
            max_address=self.max_address,
            state=MEM_COMMIT, protect=self.protect)

        for memory in memory_gen:
            base, size = memory.get_memory_range()
            if memory.is_readable() is not True:
                continue
            memory_data = self.process.read(base, size)
            if memory_data is not None:
                matches = self.find_all_aligned(base, memory_data, value)
                found.extend(matches)
        return found

    def scan_char(self, value):
        pass

    def scan_short(self, value):
        pass

    def scan_long(self, value):
        pass

    def scan_longlong(self, value):
        pass