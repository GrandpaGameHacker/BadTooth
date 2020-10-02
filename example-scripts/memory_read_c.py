import badtooth as bt
import struct

process = bt.Process("sekiro.exe")

c_boolean = '?'
c_short = 'h'
c_long = 'l'
c_int = 'i'
c_longlong = 'q'
c_float = 'f'
c_double = 'd'

c_ushort = 'H'
c_ulong = 'L'
c_uint = 'I'
c_ulonglong = 'Q'

c_sizeof = {
    c_boolean: 4,
    c_short: 2,
    c_long: 4,
    c_int: 4,
    c_longlong: 8,
    c_float: 4,
    c_double: 8,
    c_ushort: 2,
    c_ulong: 4,
    c_uint: 4,
    c_ulonglong: 8,
}

ptr_sz = 4 if process.mode else 8
c_pointer = 'I' if process.mode else 'Q'


def infer_c(value):
    if type(value) == bool:
        return c_bool

    if type(value) == int:
        if value <= 0xFFFFFFFF:
            return c_int
        else:
            return c_longlong
    if type(value) == float:
        return c_float


def to_c(c_type, data):
    return struct.pack(c_type, data)


def from_c(c_type, data):
    return struct.unpack(c_type, data)[0]


def follow_pointer(address, offsets):
    for offset in offsets:
        address = process.read(address, ptr_sz)
        address = from_c(c_pointer, address) + offset
    return address


def read_c(address, c_type):
    data = process.read(address, c_sizeof[c_type])
    return from_c(c_type, data)


def write_c(address, value, c_type):
    data = to_c(c_type, value)
    return process.write(address, data)


def write(address, value):
    c_type = infer_c(value)
    return write_c(address, value, c_type)


def read_ambiguous(address):
    data = process.read(address, 8)
    f = from_c(c_float, data[:4])
    i = from_c(c_int, data[:4])
    ih = hex(i)
    d = from_c(c_double, data)
    ll = from_c(c_longlong, data)
    llh = hex(ll)
    return f, d, i, ih, ll, llh


world_chr_man = 0x143B68E30
player_ins_offsets = [0x88, 0]
player_health_offsets = [0x88, 0x1ff8, 0x18, 0x130]
player_xyz_offsets = [0x88, 0x18, 0x28, 0x80]

player_ins = follow_pointer(world_chr_man, player_ins_offsets)
player_health = follow_pointer(world_chr_man, player_health_offsets)
player_xyz = follow_pointer(world_chr_man, player_xyz_offsets)