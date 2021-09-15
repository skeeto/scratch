# Python interface to pledge(2) and unveil(2)
# Ref: https://nullprogram.com/blog/2021/09/15/
# This is free and unencumbered software released into the public domain.
import ctypes
import os
from typing import Optional, Union

_pledge = None
try:
    _pledge = ctypes.CDLL(None, use_errno=True).pledge
    _pledge.restype = ctypes.c_int
    _pledge.argtypes = ctypes.c_char_p, ctypes.c_char_p
except Exception:
    _pledge = None

def pledge(promises: Optional[str], execpromises: Optional[str]):
    if not _pledge:
        return  # unimplemented

    r = _pledge(None if promises is None else promises.encode(),
                None if execpromises is None else execpromises.encode())
    if r == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

_unveil = None
try:
    _unveil = ctypes.CDLL(None, use_errno=True).unveil
    _unveil.restype = ctypes.c_int
    _unveil.argtypes = ctypes.c_char_p, ctypes.c_char_p
except Exception:
    _unveil = None

def unveil(path: Union[str, bytes, None], permissions: Optional[str]):
    if not _unveil:
        return  # unimplemented

    r = _unveil(path.encode() if isinstance(path, str) else path,
                None if permissions is None else permissions.encode())
    if r == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
