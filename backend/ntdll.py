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

__NtSuspendProcess = ntdll.NtSuspendProcess
__NtSuspendProcess.argtypes = [HANDLE]
__NtSuspendProcess.restype = DWORD

__NtResumeProcess = ntdll.NtResumeProcess
__NtResumeProcess.argtypes = [HANDLE]
__NtResumeProcess.restype = DWORD


def nt_success(nt_status):
    if 0 <= nt_status <= 0x3FFFFFFF:
        return True
    else:
        return False


def nt_information(nt_status):
    if 0x40000000 <= nt_status <= 0x7FFFFFFF:
        return True
    else:
        return False


def nt_warning(nt_status):
    if 0x80000000 <= nt_status <= 0xBFFFFFFF:
        return True
    else:
        return False


def nt_error(nt_status):
    if 0xC0000000 <= nt_status <= 0xFFFFFFFF:
        return True
    else:
        return False


def AdjustPrivilege(privilege, bool_enable):
    nt_status = __AdjustPrivilege(privilege, bool_enable, 0, c_byte(False))
    return nt_success(nt_status)


def NtSuspendProcess(process_handle):
    nt_status = __NtSuspendProcess(process_handle)
    return nt_success(nt_status)

def NtResumeProcess(process_handle):
    nt_status = __NtResumeProcess(process_handle)
    return nt_success(nt_status)