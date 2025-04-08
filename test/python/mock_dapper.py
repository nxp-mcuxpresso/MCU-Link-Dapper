#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# * ********************************************************************************************************* *
# *
# * Copyright 2024 NXP
# * Copyright 2025 Oidis
# *
# * SPDX-License-Identifier: BSD-3-Clause
# * The BSD-3-Clause license for this file can be found in the LICENSE.txt file included with this distribution
# * or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText
# *
# * ********************************************************************************************************* *
import ctypes
import os.path
from typing import Any, Optional

from python.dapper import Uint8Array, WebixDapper
from python.dapper.interfaces import Interface

# pylint: disable=no-member


def fcn_void_void(self: Any) -> None:
    # pylint: disable=unused-argument
    print("py_fcn_void_void called")


def fcn_async_void_void(self: Any) -> None:
    # pylint: disable=unused-argument
    print("py_fcn_async_void_void called")


def fcn_int_int(self: Any, a1: int) -> int:
    # pylint: disable=unused-argument
    print(f"py_fcn_int_int called with: {a1}")
    return a1 * 2


def fcn_async_int_int(self: Any, a1: int) -> int:
    # pylint: disable=unused-argument
    print(f"py_fcn_async_int_int called with: {a1}")
    return a1 * 2


def fcn_str_str(self: Any, s1: str) -> str:
    # pylint: disable=unused-argument
    print(f"py_fcn_str_str called with: {s1}")
    return f"{s1},_python"


def test_cb_read_data(self: Any) -> Uint8Array:
    # pylint: disable=unused-argument
    data = bytearray("test mock read data: nothing special", "utf-8")
    size = len(data)
    c_array = (ctypes.c_uint8 * size)(*data)
    buffer = Uint8Array(c_array)
    # buffer = "hello"
    return buffer


def test_cb_write_data(self: Any, data: Uint8Array) -> None:
    # pylint: disable=unused-argument
    print(f"rec: {ctypes.string_at(data.buffer)!r}")


def read_data(self: Any) -> Uint8Array:
    # pylint: disable=unused-argument
    data = bytearray("nothing special", "utf-8")
    size = len(data)
    c_array = (ctypes.c_uint8 * size)(*data)
    buffer = Uint8Array(c_array, size)
    return buffer


def write_data(self: Any, data: Uint8Array) -> None:
    # pylint: disable=unused-argument
    buffer = data
    print(f"received data len {len(buffer)}")


def fcn_throw_exception(self: Any) -> None:
    # pylint: disable=unused-argument
    raise RuntimeError("Exception from Python handler")


class MockDapper(WebixDapper):

    def __init__(self, context_path: Optional[str] = None) -> None:
        super().__init__(context_path)
        self.inbound_index = 0
        self.outbound_index = 0
        self.trace_data: dict[str, list[list[int]]] = {"inbound": [], "outbound": []}
        self.write_data_trace: list[list[Any]] = []

        self.stdout_handler = self.dummy_handler
        self.stderr_handler = self.dummy_handler
        if context_path is None:
            self.context_path = os.path.abspath(
                os.path.dirname(__file__) + "/../../build/build_wasm/webix-dapper-wasm.wasm"
            )

    def init(self) -> None:
        super().init()

        self._module.register_handler(fcn_void_void)
        self._module.register_handler(fcn_async_void_void)
        self._module.register_handler(fcn_int_int)
        self._module.register_handler(fcn_async_int_int)
        self._module.register_handler(fcn_str_str)
        self._module.register_handler(test_cb_read_data)
        self._module.register_handler(test_cb_write_data)
        self._module.register_handler(read_data)
        self._module.register_handler(write_data)
        self._module.register_handler(fcn_throw_exception)

    def dummy_handler(self, data: Any) -> None:
        # dummy
        pass

    def open(self, device: Optional[Interface] = None) -> None:
        def read_handler() -> Uint8Array:
            data = self.trace_data["inbound"][self.inbound_index]
            self.inbound_index += 1
            ArrayType = ctypes.c_uint8 * len(data)
            c_array = ArrayType()
            for i, dat in enumerate(data):
                c_array[i] = dat

            data = Uint8Array(c_array)
            return data

        def write_handler(data: Uint8Array) -> None:
            self.outbound_index += 1
            self.write_data_trace.append(list(data.buffer))

        self.read_data_handler = read_handler
        self.write_data_handler = write_handler

    @staticmethod
    def dpap_test(instance: WebixDapper, just_read: bool = False) -> None:
        mem_ap_ix = -1

        def get_coresight_ap_address(access_port: int, address: int) -> int:
            if access_port > 255:
                raise RuntimeError("Invalid value of access port")
            return address

        def _mem_reg_read(ap_ix: int, addr: int) -> int:
            instance.core_sight_write(True, get_coresight_ap_address(ap_ix, 0 * 4), 0x22000012)
            instance.core_sight_write(True, get_coresight_ap_address(ap_ix, 1 * 4), addr)
            return instance.core_sight_read(True, get_coresight_ap_address(ap_ix, 3 * 4))

        def _mem_reg_write(ap_ix: int, addr: int, data: int) -> int:
            instance.core_sight_write(True, get_coresight_ap_address(ap_ix, 0 * 4), 0x22000012)
            instance.core_sight_write(True, get_coresight_ap_address(ap_ix, 1 * 4), addr)
            instance.core_sight_write(True, get_coresight_ap_address(ap_ix, 3 * 4), data)
            return instance.core_sight_read(False, 0x04)

        def get_mem_ap() -> None:
            nonlocal mem_ap_ix
            if mem_ap_ix >= 0:
                return

            mem_ap_ix_list = [0, 1, 3]
            mem_ap_address = 0x20000000

            for item in mem_ap_ix_list:
                idr_addr = get_coresight_ap_address(item, 0xFC)
                idr = instance.core_sight_read(True, idr_addr)

                if ((idr & 0x1E000) >> 13) == 8:
                    dhcsr_reg = _mem_reg_read(item, 0xE000EDF0)
                    instance.stdout_handler(f"DHCSR register: {dhcsr_reg}")
                    _mem_reg_write(item, 0xE000EDF0, 0xA05F0000 | 0x2 | 0x1)

                    status_x = False
                    try:
                        _mem_reg_read(item, mem_ap_address)
                        status_x = True
                    except RuntimeError:
                        instance.stderr_handler(f">> Read operation on AP{item} fails")
                    _mem_reg_write(item, 0xE000EDF0, 0xA05F0000 | 0x1)
                    _mem_reg_write(item, 0xE000EDF0, 0xA05F0000)
                    if not status_x:
                        continue

                    mem_ap_ix = item
                    instance.stdout_handler(f">> Found memory access port at AP{item}")
                    break

        def mem_reg_read(addr: int) -> int:
            get_mem_ap()
            return _mem_reg_read(mem_ap_ix, addr)

        def mem_reg_write(addr: int, data: int) -> int:
            get_mem_ap()
            return _mem_reg_write(mem_ap_ix, addr, data)

        if just_read:
            mem_reg_read(0x2000001C)

        instance.connect()

        test_mem = 0x20000000
        mem_reg_read(0xE000EDF0)
        mem_reg_write(0xE000EDF0, 0xA05F0000 | 0x2 | 0x1)
        status = False

        try:
            test_value = mem_reg_read(test_mem)

            mem_reg_write(test_mem, test_value ^ 0xAAAAAAAA)
            tr = mem_reg_read(test_mem)
            mem_reg_write(test_mem, test_value)
            status = tr == (test_value ^ 0xAAAAAAAA)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            mem_reg_write(0xE000EDF0, 0xA05F0000 | 0x1)
            mem_reg_write(0xE000EDF0, 0xA05F0000)

        if not status:
            raise RuntimeError("Test connection verification failed")

    def test_void_void(self) -> None:
        self.module.test_void_void()

    def test_int_void(self) -> int:
        return self.module.test_int_void()

    def test_int_int(self, a: int) -> int:
        return self.module.test_int_int(a)

    def test_bool_void(self) -> bool:
        return self.module.test_bool_void()

    def test_bool_bool(self, a: bool) -> bool:
        return self.module.test_bool_bool(a)

    def test_float_void(self) -> float:
        return self.module.test_float_void()

    def test_float_float(self, a: float) -> float:
        return self.module.test_float_float(a)

    def test_str_void(self) -> str:
        return self.module.test_str_void()

    def test_str_str(self, a: str) -> str:
        return self.module.test_str_str(a)

    def test_struct_void(self) -> Any:
        return self.module.test_struct_void()

    def test_fcn_void_void(self) -> None:
        self.module.test_fcn_void_void()

    def test_fcn_async_void_void(self) -> None:
        self.module.test_fcn_async_void_void()

    def test_fcn_int_int(self, a1: int) -> int:
        return self.module.test_fcn_int_int(a1)

    def test_fcn_async_int_int(self, a1: int) -> int:
        return self.module.test_fcn_async_int_int(a1)

    def test_fcn_str_str(self, s1: str) -> str:
        return self.module.test_fcn_str_str(s1)

    def test_read_data(self) -> str:
        return self.module.test_read_data()

    def test_write_data(self) -> str:
        return self.module.test_write_data()

    def test_throw_exception(self) -> None:
        self.module.test_throw_exception()

    def test_fcn_throw_exception(self) -> None:
        self.module.test_fcn_throw_exception()
