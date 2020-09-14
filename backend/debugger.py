from . import kernel32
from .debug_constants import *
from .memory import *


class Debugger(object):
    def __init__(self, process_name):
        self.process = Process(process_name)
        self.attached = False
        self.breakpoints = {}

    def attach(self):
        self.attached = kernel32.DebugActiveProcess(self.process.process_id)

    def deattach(self):
        self.attached = kernel32.DebugActiveProcessStop(
            self.process.process_id)

    def breakpoint(self, address):
        pass

    def remove_breakpoint(self, address):
        pass

    def wait_next_breakpoint(self):
        pass
