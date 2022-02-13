from struct import Struct


def pack_funcs(fmt):
    struc = Struct(f"!{fmt}")
    size = struc.size

    def unpack(d):
        return struc.unpack_from(d[:size], d[size:])

    return struc.pack, unpack


pack_int8, unpack_int8 = pack_funcs("b")
pack_int16, unpack_int16 = pack_funcs("h")
pack_int32, unpack_int32 = pack_funcs("i")
pack_int64, unpack_int64 = pack_funcs("q")
pack_uint8, unpack_uint8 = pack_funcs("B")
pack_uint16, unpack_uint16 = pack_funcs("H")
pack_uint32, unpack_uint32 = pack_funcs("I")
pack_uint64, unpack_uint64 = pack_funcs("Q")
_, unpack_uint8_int32 = pack_funcs("Bi")


def pack_string(v):
    return pack_uint32(len(v)) + v.encode("utf8")


def unpack_string(d):
    length, d = unpack_uint32(d)
    return d.decode("utf8"), d[length:]


def pack_bytes(v):
    return pack_uint32(len(v)) + v


def unpack_bytes(d):
    length, d = unpack_uint32(d)
    return d, d[length:]


def unpack_header(d):
    code, d = unpack_uint16(d)
    value, d = unpack_bytes(d)
    return (code, value), d


def unpack_multi(d, num, unpack_func):
    vals = []
    for _ in range(num):
        val, d = unpack_func(d)
        vals.append(val)
    return vals, d


def unpack_uuid(d):
    return d[:16], d[16:]


def unpack_data_element(d, descriptor):
    num_data, d = unpack_uint32(d)
    return d[:num_data], d[num_data:]
