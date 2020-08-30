"""
Script to interactively trace data changes in memory ranges
Useful to reverse engineer data structures
"""
__version__ = 0.02
import sys
import code
import time
import struct

from backend import *


def trace(address, size, wait=0.05):
    print(f"Watching {hex(address)}:{hex(size)}")
    while True:
        data0 = target.read(address, size)
        time.sleep(wait)
        data1 = target.read(address, size)
        result = compare_bytes(address, data0, data1)
        if result != "":
            print(result)


def ftrace(address, size, file_name, wait=0.05):
    print(f"Watching {hex(address)}:{hex(size)}")
    with open(file_name, "w+") as f_output:
        while True:
            data0 = target.read(address, size)
            time.sleep(wait)
            data1 = target.read(address, size)
            result = compare_bytes(address, data0, data1)
            if result != "":
                f_output.write(result)

def compare_bytes(address, data0, data1):
    output = ""
    assert len(data0) == len(data1)
    if byte_size == 4:
        unpack_str = "I" * (len(data0) // byte_size)
    if byte_size == 8:
        unpack_str = "Q" * (len(data0) // byte_size)
    unpack0 = struct.unpack(unpack_str, data0)
    unpack1 = struct.unpack(unpack_str, data1)
    c_addr = 0
    for item0, item1 in zip(unpack0, unpack1):
        if item0 != item1:
            output = output + hex(address) + " + " + hex(c_addr) + " : "
            output = output + hex(item0)[2:].zfill(byte_size * 2) + " -->"
            output = output + hex(item1)[2:].zfill(byte_size * 2) + "\n\n"
        c_addr = c_addr + byte_size
    return output


if len(sys.argv) != 2:
    print("ScriptError: wrong arguments\nExpected process_name")
    quit()
process_name = sys.argv[1]
target = Process(get_process_first(process_name).get_pid())
byte_size = 8
if is_process_32bit(target.handle):
    byte_size = 4
code.interact(banner=f"Memory Tracer Tool v{__version__}", local=locals())


if __name__ == '__main__':
    main()
