from backend import *

class Scanner():
    def __init__(self, process_name):
        self.process_entry = get_process_first(process_name)
        self.process = Process(self.process_entry.get_pid())
        self.pointer_size = {True: 4, False: 8}[self.process.is_32bit()]
        self.process_name = self.process_entry.get_name()
        # scan settings
        self.default_protection_flags = "w-x+"
        self.protection_flags = self.default_protection_flags
        self.default_alignment = 4
        self.alignment = self.default_alignment

    def set_scan_options(self, protection_flags, alignment):
        pass

    def scan_aob(self, value):
        pass
