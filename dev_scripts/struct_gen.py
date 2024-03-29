"""Intended to help generate ctypes structs from Windows API Structures"""

struct_data = """
typedef struct _PEB_LDR_DATA {
    UINT8 _PADDING_[12];
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
"""

def convert_struct(struct_s):
    python_struct = "class "
    tab_str = "    "
    struct_lines = struct_s.splitlines()
    struct_lines = struct_lines[1:]
    head = struct_lines[0]
    head = head.replace("typedef", "")
    head = head.replace("struct", "")
    head = head.replace("{", "")
    head = head.replace("_", "", 1)
    struct_name = "".join(head.split())
    python_struct += struct_name + "(Structure):\n"
    field_lines = struct_lines[1:-1]
    python_struct += tab_str + "_fields_ = [\n"
    for field in field_lines:
        if field != field_lines[-1]:
            last_field = False
        else:
            last_field = True
        field = field.strip()
        field = field.replace(";", "")
        array_n = ""
        array_l = field.find("[")
        array_r = field.find("]")
        if array_l != -1:
            array_n += "*"
            array_n += field[array_l+1:array_r]
            field = field[0:array_l-1]
        parts = field.split(" ")
        parts = [part for part in parts if part]
        if not last_field:
            python_struct += tab_str * 2 + f"(\"{parts[1]}\", {parts[0]}{array_n}),\n"
        else:
            python_struct += tab_str * 2 + f"(\"{parts[1]}\", {parts[0]})\n{tab_str}]"
    return python_struct


print(convert_struct(struct_data))
