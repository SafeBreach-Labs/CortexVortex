"""
This module provides utilities for creating an hardlink without write permissions.

More info about it can be found in this blogpost:
https://googleprojectzero.blogspot.com/2015/12/between-rock-and-hard-link.html
"""
import ctypes
import os.path
import logging
from ctypes.wintypes import LPVOID, ULONG, BOOL
from ctypes import wintypes, POINTER
import win32file
import win32con

NTSTATUS = wintypes.LONG
NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)
FILE_LINK_INFORMATION = 72


class _IOStatusBlockResult(ctypes.Union):
    _fields_ = [
        ("Status", NTSTATUS),
        ("Pointer", LPVOID),
    ]

class IOStatusBlock(ctypes.Structure):
    """
    https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
    """
    _fields_ = [
        ("dummy_union_name", _IOStatusBlockResult),
        ("Information", POINTER(ULONG)),
    ]

class _FileLinkInformationDummyUnionName(ctypes.Union):
    _fields_ = [
        ("replace_if_exists", BOOL),
        ("Flags", ctypes.c_ulong)
    ]


NtSetInformationFile = NTDLL.NtSetInformationFile
NtSetInformationFile.argtypes = [ctypes.wintypes.HANDLE,  # FileHandle
                                 POINTER(IOStatusBlock),  # IoStatusBlock
                                 ctypes.wintypes.LPVOID,  # FileInformation
                                 ctypes.wintypes.ULONG,   # Length
                                 ctypes.c_uint,  # FileInformationClass
                                 ]
NtSetInformationFile.restype = NTSTATUS

# pylint: disable=attribute-defined-outside-init
def file_link_information_factory(length_file_name):
    """
    Generate dynamically sized struct FILE_LINK_INFORMATION
    :param length_file_name: length of the field 'file_name'
    :return: FILE_LINK_INFORMATION instance.
    """
    class _FileLinkInformation(ctypes.Structure):
        """
        https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_link_information
        """
        _fields_ = [
            ("dummy_union_name", _FileLinkInformationDummyUnionName),
            ("root_directory", ctypes.wintypes.HANDLE),
            ("file_name_length", ctypes.c_ulong),
            ("file_name", ctypes.c_wchar * length_file_name),
        ]
    return _FileLinkInformation()

def create_hard_link(src: str, dst: str):
    """
    Create hardlink via NtSetInformationFile.

    Followed the source code in:
    https://github.com/googleprojectzero/symboliclink-testing-tools/blob/00c0fe4cefcd2a62c887fe6117abc02bc98bb9fb/CommonUtils/Hardlink.cpp
    :param src: Path of the file that will be pointed by the hardlink
    :param dst: Path of the hardlink that will be created
    :return: Ntstatus code
    """
    # Path is required to be in win32 device-namespace
    source_path_absolute = rf"\??\\{os.path.abspath(dst)}"
    try:
        file_handle = win32file.CreateFile(src, win32file.GENERIC_READ,
                                           win32file.FILE_SHARE_READ,
                                           None,
                                           win32con.OPEN_EXISTING, 0, None)
    except Exception as e:
        logging.error("Exception at create_hard_link %s",e)
        raise

    io_status = IOStatusBlock()
    path_hard_link_unicode = ctypes.create_unicode_buffer(source_path_absolute)
    size_hard_link_path = ctypes.sizeof(path_hard_link_unicode)
    file_link_information = file_link_information_factory(size_hard_link_path)

    file_link_information.file_name_length = size_hard_link_path - ctypes.sizeof(ctypes.c_wchar)
    file_link_information.file_name = source_path_absolute
    dummy_union_name = _FileLinkInformationDummyUnionName()
    dummy_union_name.replace_if_exists = True
    file_link_information.dummy_union_name = dummy_union_name
    file_link_info_sizeof = ctypes.sizeof(file_link_information)
    try:
        nt_status = NtSetInformationFile(file_handle.handle, ctypes.byref(io_status),
                                        ctypes.byref(file_link_information), file_link_info_sizeof,
                                        FILE_LINK_INFORMATION)
    finally:
        file_handle.close()

    return nt_status
