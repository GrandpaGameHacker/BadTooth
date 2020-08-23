"""
Script to interactively trace data changes in memory ranges
"""
__version__ = 0.01
import sys
import code
import time
import struct

from backend import *


def trace_memory(address, size, wait=0.05):
    while True:
        data0 = target.read(address, size)
        time.sleep(wait)
        data1 = target.read(address, size)
        compare_bytes(address, data0, data1)


def compare_bytes(address, data0, data1):
    assert len(data0) == len(data1)
    unpack_str = "I" * (len(data0) // 4)
    unpack0 = struct.unpack(unpack_str, data0)
    unpack1 = struct.unpack(unpack_str, data1)
    c_addr = 0
    for item0, item1 in zip(unpack0, unpack1):
        if item0 != item1:
            print(hex(address)+" + "+hex(c_addr),"\n", hex(item0)[2:].zfill(8)+"\n", hex(item1)[2:].zfill(8) + "\n\n")
        c_addr = c_addr + 4


if len(sys.argv) != 2:
    print("ScriptError: wrong arguments\n")
    quit()
process_name = sys.argv[1]
target = Process(get_process_first(process_name).get_pid())
code.interact(banner=f"Memory Tracer Tool v{__version__}", local=locals())


if __name__ == '__main__':
    main()
