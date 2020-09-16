from .kernel32_structs import *
from .debug_constants import *
from .memory import *
import threading
from time import sleep


class Debugger(object):
    def __init__(self, process_name):
        enable_se_debug()
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
        thread = threading.Thread(target=self.alive_loop)
        thread.start()

    def detach(self):
        self.attached = kernel32.DebugActiveProcessStop(
            self.process.process_id)

    def process_debug_event(self, debug_event):
        event_handler = self._debug_events[debug_event.event_code]
        return event_handler(debug_event)

    def alive_loop(self):
        process_alive = True
        while process_alive:
            process_alive = self.process.is_alive()
            sleep(0.1)
        print("Debugger Exiting!")
        self = kernel32.GetCurrentProcess()
        kernel32.TerminateProcess(self, 0)

    def loop(self):
        debug_event = DEBUG_EVENT()
        while True:
            if not kernel32.WaitForDebugEvent(debug_event, 50000):
                return
            continue_status = self.process_debug_event(debug_event)
            kernel32.ContinueDebugEvent(
                debug_event.process_id, debug_event.thread_id, continue_status)
            self.restore_breakpoints()

    def breakpoint_event(self, debug_event):
        address = debug_event.exception_address
        print(f"Breakpoint hit at {hex(address)}")
        code = self.process.read(address, 15)
        code = self.process.dsm.dis_all(code, address, 0)
        for instr in code:
            if instr == code[0]:
                print(f"--> {instr}")
            print(f"-- {instr}")
        self.clear_hw_breakpoint_address(address)

    def exception_event(self, debug_event):
        if debug_event.exception_code == STATUS_SINGLE_STEP:
            self.breakpoint_event(debug_event)
            return DBG_CONTINUE
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

    def interactive_breakpoint(self):
        pass

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

    def clear_hw_breakpoints(self):
        self.process.suspend()
        thread_gen = self.process.yield_threads()
        for thread in thread_gen:
            thread_handle = kernel32.OpenThread(thread.tid)
            ctx = kernel32.GetThreadContext(self.process.mode, thread_handle)
            ctx.clear_all_Drx()
            kernel32.SetThreadContext(self.process.mode, thread_handle, ctx)
            kernel32.CloseHandle(thread_handle)
        self.process.resume()

    def set_hw_breakpoint(self, address, drx, length, rwx):
        self.process.suspend()
        thread_gen = self.process.yield_threads()
        for thread in thread_gen:
            thread_handle = kernel32.OpenThread(thread.tid)
            ctx = kernel32.GetThreadContext(self.process.mode, thread_handle)
            if drx == 0:
                ctx.Dr0 = address
                ctx.Dr7.fields.l0 = 1
                ctx.Dr7.fields.g0 = 1
                ctx.Dr7.fields.rw0 = rwx
                ctx.Dr7.fields.len0 = length
            elif drx == 1:
                ctx.Dr1 = address
                ctx.Dr7.fields.l1 = 1
                ctx.Dr7.fields.g1 = 1
                ctx.Dr7.fields.rw1 = rwx
                ctx.Dr7.fields.len0 = length
            elif drx == 2:
                ctx.Dr2 = address
                ctx.Dr7.fields.l2 = 1
                ctx.Dr7.fields.g2 = 1
                ctx.Dr7.fields.rw2 = rwx
                ctx.Dr7.fields.len0 = length
            elif drx == 3:
                ctx.Dr3 = address
                ctx.Dr7.fields.l3 = 1
                ctx.Dr7.fields.g3 = 1
                ctx.Dr7.fields.rw2 = rwx
                ctx.Dr7.fields.len0 = length
            kernel32.SetThreadContext(self.process.mode, thread_handle, ctx)
            kernel32.CloseHandle(thread_handle)
        self.breakpoints[drx] = (address, length, rwx)
        self.process.resume()

    def clear_hw_breakpoint(self, drx):
        self.process.suspend()
        thread_gen = self.process.yield_threads()
        for thread in thread_gen:
            thread_handle = kernel32.OpenThread(thread.tid)
            ctx = kernel32.GetThreadContext(self.process.mode, thread_handle)
            if drx == 0:
                ctx.Dr6 = 0
                ctx.Dr0 = 0
                ctx.Dr7.fields.l0 = 0
                ctx.Dr7.fields.g0 = 0
                ctx.Dr7.fields.rw0 = 0
                ctx.Dr7.fields.len0 = 0
            elif drx == 1:
                ctx.Dr6 = 0
                ctx.Dr1 = 0
                ctx.Dr7.fields.l1 = 0
                ctx.Dr7.fields.g1 = 0
                ctx.Dr7.fields.rw1 = 0
                ctx.Dr7.fields.len1 = 0
            elif drx == 2:
                ctx.Dr6 = 0
                ctx.Dr2 = 0
                ctx.Dr7.fields.l2 = 0
                ctx.Dr7.fields.g2 = 0
                ctx.Dr7.fields.rw2 = 0
                ctx.Dr7.fields.len2 = 0
            elif drx == 3:
                ctx.Dr6 = 0
                ctx.Dr3 = 0
                ctx.Dr7.fields.l3 = 0
                ctx.Dr7.fields.g3 = 0
                ctx.Dr7.fields.rw3 = 0
                ctx.Dr7.fields.len3 = 0
            kernel32.SetThreadContext(self.process.mode, thread_handle, ctx)
            kernel32.CloseHandle(thread_handle)
        self.process.resume()

    def clear_hw_breakpoint_address(self, address):
        self.process.suspend()
        thread_gen = self.process.yield_threads()
        for thread in thread_gen:
            thread_handle = kernel32.OpenThread(thread.tid)
            ctx = kernel32.GetThreadContext(self.process.mode, thread_handle)
            if ctx.Dr0 == address:
                ctx.Dr6 = 0
                ctx.Dr0 = 0
                ctx.Dr7.fields.l0 = 0
                ctx.Dr7.fields.g0 = 0
                ctx.Dr7.fields.rw0 = 0
                ctx.Dr7.fields.len0 = 0
            if ctx.Dr1 == address:
                ctx.Dr6 = 0
                ctx.Dr1 = 0
                ctx.Dr7.fields.l1 = 0
                ctx.Dr7.fields.g1 = 0
                ctx.Dr7.fields.rw1 = 0
                ctx.Dr7.fields.len1 = 0
            if ctx.Dr2 == address:
                ctx.Dr6 = 0
                ctx.Dr2 = 0
                ctx.Dr7.fields.l2 = 0
                ctx.Dr7.fields.g2 = 0
                ctx.Dr7.fields.rw2 = 0
                ctx.Dr7.fields.len2 = 0
            if ctx.Dr3 == address:
                ctx.Dr6 = 0
                ctx.Dr3 = 0
                ctx.Dr7.fields.l3 = 0
                ctx.Dr7.fields.g3 = 0
                ctx.Dr7.fields.rw3 = 0
                ctx.Dr7.fields.len3 = 0
            kernel32.SetThreadContext(self.process.mode, thread_handle, ctx)
            kernel32.CloseHandle(thread_handle)
        self.process.resume()

    def restore_breakpoints(self):
        for i in self.breakpoints:
            address, length, rwx = self.breakpoints[i]
            self.set_hw_breakpoint(address, i, length, rwx)
