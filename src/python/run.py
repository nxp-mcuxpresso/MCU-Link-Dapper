#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# * ********************************************************************************************************* *
# *
# * Copyright 2024 NXP
# *
# * SPDX-License-Identifier: BSD-3-Clause
# * The BSD-3-Clause license for this file can be found in the LICENSE.txt file included with this distribution
# * or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText
# *
# * ********************************************************************************************************* *
import argparse
import cProfile
import logging
import os
import sys
from datetime import datetime

from python.dapper.webix_dapper import DapperFactory
from python.mock_dapper import MockDapper

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dapper probe validation executor")
    parser.add_argument("--iterations", type=int, default=1, help="number of iterations")
    parser.add_argument("--profile", action="store_true", help="enable profiling")
    parser.add_argument("--list", action="store_true", help="list probes")
    parser.add_argument("--verbose", action="store_true", help="verbose log")

    args = parser.parse_args()

    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.DEBUG
        logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")

    DapperFactory.set_wasm_path(
        os.path.abspath(
            os.path.dirname(__file__) + "/../../build/build_wasm/webix-dapper-wasm.wasm"
        )
    )

    probes = DapperFactory.list_probes()
    print("Detected probes:\n ***")
    for probe in probes:
        print(f"{probe.serial_no}: {probe.description} ({probe.type})")

    probe_label = "probe" if len(probes) == 1 else "probes"
    print(f" *** {len(probes)} {probe_label} detected ***")
    if args.list:
        sys.exit(0)

    if len(probes) == 0:
        print("No probes detected")
        sys.exit(1)

    probe = DapperFactory.create_probe(probes[0])
    probe.connect()
    probe.close()
    probe = DapperFactory.create_probe(probes[0])

    print(f"\nSelected probe {probes[0].serial_no}")

    info = probe.get_probe_dap_info()

    print(f"Probe info: {info.__dict__}")

    def run_test() -> None:
        dt = datetime.now()
        for _ in range(args.iterations):
            MockDapper.dpap_test(probe)
        print(f"elapsed: {(datetime.now() - dt).total_seconds()} s")

    if args.profile:
        cProfile.run("run_test()", os.path.abspath(os.path.dirname(__file__)) + "/profiling.prof")
    else:
        run_test()
    print("\n*** I'm genius, seriously! ***\n")
