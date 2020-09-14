from .kernel32_structs import *
from .debug_constants import *
from .memory import *


class Debugger(object):
    def __init__(self, process_name):
        self.process = Process(process_name)
        self.attached = False
        self.breakpoints = {}
        self._debug_events = {
            EXCEPTION_DEBUG_EVENT: self.exception_event,
            CREATE_THREAD_DEBUG_EVENT: self.create_thread_event,
            CREATE_PROCESS_DEBUG_EVENT: self.create_process_event,
            EXIT_THREAD_DEBUG_EVENT: self.exit_thread_event,
            EXIT_PROCESS_DEBUG_EVENT: self.exit_process_event,
            LOAD_DLL_DEBUG_EVENT: self.load_dll_event,
            UNLOAD_DLL_DEBUG_EVENT: self.unload_dll_event,
            OUTPUT_DEBUG_STRING_EVENT: self.output_string_event,
            RIP_EVENT: self.rip_event,
        }

    def attach(self):
        self.attached = kernel32.DebugActiveProcess(self.process.process_id)
        self.loop()

    def detach(self):
        self.attached = kernel32.DebugActiveProcessStop(
            self.process.process_id)

    def breakpoint(self, address):
        pass

    def process_debug_event(self, debug_event):
        event_handler = self._debug_events[debug_event.event_code]
        return event_handler(debug_event)

    def loop(self):
        debug_event = DEBUG_EVENT()
        while True:
            if not kernel32.WaitForDebugEvent(debug_event, 0xFFFFFFFF):
                return
            continue_status = self.process_debug_event(debug_event)
            kernel32.ContinueDebugEvent(
                debug_event.process_id, debug_event.thread_id, continue_status)

    def exception_event(self, debug_event):
        return DBG_EXCEPTION_NOT_HANDLED

    def create_thread_event(self, debug_event):
        return DBG_CONTINUE

    def create_process_event(self, debug_event):
        return DBG_CONTINUE

    def exit_thread_event(self, debug_event):
        return DBG_CONTINUE

    def exit_process_event(self, debug_event):
        return DBG_CONTINUE

    def load_dll_event(self, debug_event):
        return DBG_CONTINUE

    def unload_dll_event(self, debug_event):
        return DBG_CONTINUE

    def output_string_event(self, debug_event):
        debug_string = debug_event.u.DebugString
        debug_string_len = debug_string.nDebugStringLength
        if debug_string.fUnicode:
            debug_string_len = debug_string.nDebugStringLength * 2
        debug_string_data = self.process.read(
            debug_string.lpDebugStringData, debug_string_len)
        if debug_string.fUnicode:
            print(debug_string_data[:-2].decode("UTF-16"))
        else:
            print(debug_string_data[:-2].decode("ASCII"))
        return DBG_CONTINUE

    def rip_event(self, debug_event):
        return DBG_CONTINUE
