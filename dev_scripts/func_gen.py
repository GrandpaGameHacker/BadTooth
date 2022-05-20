"""Intended to help generate ctypes function definitions from Windows API definitions"""
dll_name = "psapi"

function_to_convert = """
BOOL GetModuleInformation(
  HANDLE       hProcess,
  HMODULE      hModule,
  LPMODULEINFO lpmodinfo,
  DWORD        cb
);
"""


def convert_function(function_s):
    function_lines = function_s.splitlines()
    function_lines = function_lines[1:]
    head = function_lines[0]
    args = function_lines[1:-1]
    restype, function_name = head.split(" ")
    function_name = function_name.replace("(", "")
    python_function = "__" + function_name
    python_function += " = " + dll_name + "." + function_name
    python_function += "\n__" + function_name
    python_function += ".argtypes = ["
    arg_names = ""
    for arg in args:
        last_arg = False
        if args.index(arg) == len(args)-1:
            last_arg = True
        arg_type, arg_name = arg.split()
        arg_names += arg_name + " "
        arg_name = arg_name.replace(",", "")
        if not last_arg:
            python_function += f"{arg_type}, "
        else:
            python_function += f"{arg_type}] "
    python_function += "\n__" + function_name
    python_function += ".restype = " + restype
    python_function = f"# {function_name}({arg_names});\n" + python_function

    return python_function


print(convert_function(function_to_convert))
