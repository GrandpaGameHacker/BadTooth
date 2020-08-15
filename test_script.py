import windows_api.kernel32
import windows_api.winnt_constants as winnt_constants


def get_pid(process_name):
    hSnap = windows_api.kernel32.CreateToolhelp32Snapshot(
        winnt_constants.TH32CS_SNAPPROCESS, 0)
    proc_entry = windows_api.kernel32.Process32First(hSnap)
    process = proc_entry.szExeFile.decode("ASCII")
    if process == process_name:
        windows_api.kernel32.CloseHandle(hSnap)
        return proc_entry.th32ProcessID
    while windows_api.kernel32.Process32Next(hSnap, proc_entry):
        process = proc_entry.szExeFile.decode("ASCII")
        if process == process_name:
            windows_api.kernel32.CloseHandle(hSnap)
            return proc_entry.th32ProcessID


def get_pids(process_name):
    pids = []
    hSnap = windows_api.kernel32.CreateToolhelp32Snapshot(
        winnt_constants.TH32CS_SNAPPROCESS, 0)
    proc_entry = windows_api.kernel32.Process32First(hSnap)
    process = proc_entry.szExeFile.decode("ASCII")
    if process == process_name:
        pids.append(proc_entry.th32ProcessID)
    while windows_api.kernel32.Process32Next(hSnap, proc_entry):
        process = proc_entry.szExeFile.decode("ASCII")
        if process == process_name:
            pids.append(proc_entry.th32ProcessID)
    windows_api.kernel32.CloseHandle(hSnap)
    return pids


pid = get_pid("notepad.exe")
handle = windows_api.kernel32.OpenProcess(pid)
memory = windows_api.kernel32.VirtualAllocEx(handle, 0, 2048)
print("ALLOCATED:", hex(memory))
windows_api.kernel32.WriteProcessMemory(handle, memory, b'test')
buffer = windows_api.kernel32.ReadProcessMemory(handle, memory, 4)
print(buffer)