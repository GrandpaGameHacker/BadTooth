from ctypes import *
from ctypes.wintypes import *


class LIST_ENTRY(Structure):
    pass

class LDR_DATA_TABLE_ENTRY(Structure):
    pass

class LDR_LIST_ENTRY_U(Union):
    _fields_ = [
        ("list", POINTER(LIST_ENTRY)),
        ("entry", POINTER(LDR_DATA_TABLE_ENTRY)),
    ]

LIST_ENTRY._fields_ = [
    ("Flink", LDR_LIST_ENTRY_U),
    ("Blink", LDR_LIST_ENTRY_U)
]

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR)
    ]

LDR_DATA_TABLE_ENTRY._fields_ = [
        ("Reserved", LPVOID*2),
        ("InMemoryOrderLinks", LIST_ENTRY),
        ("Reserved", LPVOID*2),
        ("DllBase", LPVOID),
        ("EntryPoint", LPVOID),
        ("Reserved3", LPVOID),
        ("FullDllName", UNICODE_STRING),
        ("Reserved", BYTE*8),
        ("Reserved", LPVOID*3),
        ("Reserved6", LPVOID),
        ("TimeDateStamp", ULONG)
    ]

class PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Reserved", BYTE * 8),
        ("Reserved", LPVOID * 3),
        ("InMemoryOrderModuleList", LIST_ENTRY)
    ]


class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR)
    ]


class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("Reserved", BYTE * 16),
        ("Reserved", LPVOID * 10),
        ("ImagePathName", UNICODE_STRING),
        ("CommandLine", UNICODE_STRING)
    ]


class PEB(Structure):
    _fields_ = [
        ("Reserved1", BYTE * 2),
        ("BeingDebugged", BYTE),
        ("Reserved2", BYTE),
        ("Reserved3", LPVOID * 2),
        ("Ldr", POINTER(PEB_LDR_DATA)),
        ("ProcessParameters", POINTER(RTL_USER_PROCESS_PARAMETERS)),
        ("Reserved4", LPVOID * 3),
        ("AtlThunkSListPtr", LPVOID),
        ("Reserved5", LPVOID),
        ("Reserved6", ULONG),
        ("Reserved7", LPVOID),
        ("Reserved8", ULONG),
        ("AtlThunkSListPtr32", ULONG),
        ("Reserved9", LPVOID * 45),
        ("Reserved10", BYTE * 96),
        ("PostProcessInitRoutine", LPVOID),
        ("Reserved11", BYTE * 128),
        ("Reserved12", LPVOID),
        ("SessionId", ULONG)
    ]


class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("Reserved1", LPVOID),
        ("PebBaseAddress", POINTER(PEB)),
        ("Reserved", LPVOID*2),
        ("UniqueProcessId", PULONG),
        ("Reserved3", LPVOID)
    ]
    # def walk_modules(self):
    #     modules = []
    #     if not self.PebBaseAddress.contents:
    #         return None
    #     peb = self.PebBaseAddress.contents
    #     if not peb.Ldr.contents:
    #         return None
    #     ldr = peb.Ldr.contents
    #     if not ldr.InMemoryOrderModuleList.contents:
    #         return None
    #     mods = ldr.InMemoryOrderModuleList.contents
    #     if not mods.Flink.entry.contents:
    #         return None
    #     current_module = mods.Flink
    #     while current_module is not None:
    #         mod_data = current_module.entry.contents
    #         mod_name = mod_data.FullDllName
    #         print(mod_name)
    #         mod_base = mod_data.DllBase
    #         mod_entry = mod_data.EntryPoint
    #         modules.append((mod_name, mod_base, mod_entry))
    #         current_module = current_module.Flink
    #         if not current_module.Flink.contents:
    #             current_module = None
    #     return modules

