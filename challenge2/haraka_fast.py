from ctypes import *


haraka_lib = cdll.LoadLibrary("haraka")


def haraka256(msg: bytes) -> bytes:
    out = create_string_buffer(b'\x00' * 32)
    haraka_lib.haraka256_256(out, msg)
    return out.raw[:32]


def haraka512(msg: bytes) -> bytes:
    out = create_string_buffer(b'\x00' * 32)
    haraka_lib.haraka512_256(out, msg)
    return out.raw[:32]
