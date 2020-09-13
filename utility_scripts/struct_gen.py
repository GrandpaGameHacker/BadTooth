import sys


def convert_struct(struct_s):
    python_struct = "class "
    tab_str = "    "
    struct_lines = struct_s.splitlines()
    head = struct_lines[0]
    head = head.replace("typedef", "")
    head = head.replace("struct", "")
    head = head.replace("{", "")
    head = head.replace("_", "")
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
        parts = field.split(" ")
        parts = [part for part in parts if part]
        if(not last_field):
            python_struct += tab_str * 2 + f"(\"{parts[1]}\", {parts[0]}),\n"
        else:
            python_struct += tab_str * 2 + f"(\"{parts[1]}\", {parts[0]})\n{tab_str}]"
    return python_struct


with open(sys.argv[1]) as f:
    struct_data = f.read()
    print(convert_struct(struct_data))
