from ctypes import *
from ctypes.wintypes import *

SE_CREATE_TOKEN_PRIVILEGE = 2
SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = 3
SE_LOCK_MEMORY_PRIVILEGE = 4
SE_INCREASE_QUOTA_PRIVILEGE = 5
SE_MACHINE_ACCOUNT_PRIVILEGE = 6
SE_TCB_PRIVILEGE = 7
SE_SECURITY_PRIVILEGE = 8
SE_TAKE_OWNERSHIP_PRIVILEGE = 9
SE_LOAD_DRIVER_PRIVILEGE = 10
SE_SYSTEM_PROFILE_PRIVILEGE = 11
SE_SYSTEMTIME_PRIVILEGE = 12
SE_PROF_SINGLE_PROCESS_PRIVILEGE = 13
SE_INC_BASE_PRIORITY_PRIVILEGE = 14
SE_CREATE_PAGEFILE_PRIVILEGE = 15
SE_CREATE_PERMANENT_PRIVILEGE = 16
SE_BACKUP_PRIVILEGE = 17
SE_RESTORE_PRIVILEGE = 18
SE_SHUTDOWN_PRIVILEGE = 19
SE_DEBUG_PRIVILEGE = 20
SE_AUDIT_PRIVILEGE = 21
SE_SYSTEM_ENVIRONMENT_PRIVILEGE = 22
SE_CHANGE_NOTIFY_PRIVILEGE = 23
SE_REMOTE_SHUTDOWN_PRIVILEGE = 24
SE_UNDOCK_PRIVILEGE = 25
SE_SYNC_AGENT_PRIVILEGE = 26
SE_ENABLE_DELEGATION_PRIVILEGE = 27
SE_MANAGE_VOLUME_PRIVILEGE = 28
SE_IMPERSONATE_PRIVILEGE = 29
SE_CREATE_GLOBAL_PRIVILEGE = 30
SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE = 31
SE_RELABEL_PRIVILEGE = 32
SE_INC_WORKING_SET_PRIVILEGE = 33
SE_TIME_ZONE_PRIVILEGE = 34
SE_CREATE_SYMBOLIC_LINK_PRIVILEGE = 35
SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE = 36

# undocumented
ntdll = WinDLL('ntdll', use_last_error=True)
__AdjustPrivilege = ntdll.RtlAdjustPrivilege
__AdjustPrivilege.argtypes = [ULONG, BOOLEAN, BOOLEAN, POINTER(BOOLEAN)]
__AdjustPrivilege.restype = DWORD  # NTSTATUS


def NT_SUCCESS(Status):
    if Status >= 0 and Status <= 0x3FFFFFFF:
        return True
    else:
        return False


def NT_INFORMATION(Status):
    if Status >= 0x40000000 and Status <= 0x7FFFFFFF:
        return True
    else:
        return False


def NT_WARNING(Status):
    if Status >= 0x80000000 and Status <= 0xBFFFFFFF:
        return True
    else:
        return False


def NT_ERROR(Status):
    if Status >= 0xC0000000 and Status <= 0xFFFFFFFF:
        return True
    else:
        return False


def AdjustPrivilege(privilege, bool_enable):
    return __AdjustPrivilege(privilege, bool_enable, 0, c_byte(False))
    # Returns NTSTATUS_SUCCESS on success, NTSTATUS code on failure.
