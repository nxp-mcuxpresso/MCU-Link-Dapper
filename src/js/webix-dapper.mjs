/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license for this file can be found in the LICENSE.txt file included with this distribution
 * or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText
 */
import loadWasm from "../../build/build_wasm/webix-dapper-wasm.js";

let stdoutHandler = () => {
    // override me
};

let stderrHandler = () => {
    // override me
};

let readDataHandler = async () => {
    // override me
};

let writeDataHandler = async () => {
    // override me
};

async function readData() {
    return readDataHandler();
}

async function writeData(data) {
    await writeDataHandler(data);
}

function stdout(data) {
    stdoutHandler(data);
}

function stderr(data) {
    stderrHandler(data);
}

function extendBuffer(data, packetSize) {
    function isView(source) {
        return source.buffer !== undefined;
    }

    const arrayBuffer = isView(data) ? data.buffer : data;
    if (arrayBuffer.byteLength === packetSize) {
        return isView(data) ? data : new Uint8Array(data);
    }
    const length = Math.min(arrayBuffer.byteLength, packetSize);
    const result = new Uint8Array(length);
    result.set(new Uint8Array(arrayBuffer));

    return result;
}

export class ProbeInfo {
    vendorId;
    productId;
    serialNo;
    firmwareVer;
    targetVendor;
    targetName;
    boardVendor;
    boardName;
    productFwVer;
    capabilities;
}

export class ProbeCapabilities {
    swd;
    jtag;
}

export class WebixDapper {
    module = null;
    device = null;

    interfaceNumber = undefined;
    endpointIn = null;
    endpointOut = null;
    packetSize = 64;

    alwaysControlTransfer = false;
    trace = false;
    traceData = {inbound: [], outbound: []};

    constructor() {
        this.setStdoutHandler(null);
        this.setStderrHandler(null);

        globalThis.readData = readData;
        globalThis.writeData = writeData;
        globalThis.stdout = stdout;
        globalThis.stderr = stderr;
    }

    /**
     * Register handler for stdout data processing, default is console.log(..)
     * @param handler Specify string processing function.
     */
    setStdoutHandler(handler) {
        if (typeof handler === "function") {
            stdoutHandler = handler;
        } else {
            stdoutHandler = (data) => {
                console.log(data);
            };
        }
    }

    /**
     * Register handler for stderr data processing, default is console.error(..)
     * @param handler Specify string processing function.
     */
    setStderrHandler(handler) {
        if (typeof handler === "function") {
            stderrHandler = handler;
        } else {
            stderrHandler = (data) => {
                console.error(data);
            };
        }
    }

    setReadDataHandler(handler) {
        if (typeof handler === "function") {
            readDataHandler = handler;
        } else {
            readDataHandler = async () => {
                if (this.interfaceNumber === undefined) {
                    throw new Error("Device needs to be opened first.");
                }
                let result;
                if (this.endpointIn) {
                    result = await this.device.transferIn(
                        this.endpointIn.endpointNumber,
                        this.packetSize
                    );
                } else {
                    result = await this.device.controlTransferIn(
                        {
                            requestType: "class",
                            recipient: "interface",
                            request: 0x01,
                            value: 0x100,
                            index: this.interfaceNumber
                        },
                        this.packetSize
                    );
                }
                const data = new Uint8Array(result.data.buffer);
                if (this.trace) {
                    this.traceData.inbound.push(data);
                }
                return data;
            };
        }
    }

    setWriteDataHandler(handler) {
        if (typeof handler === "function") {
            writeDataHandler = handler;
        } else {
            writeDataHandler = async (data) => {
                if (this.interfaceNumber === undefined) {
                    throw new Error("Device needs to be opened first.");
                }

                // TODO(mkelnar) data from memory view contains complete HEAP8 data, so copy only array content
                //  can we replace this copy by some parametrisation?
                const dataBuff = new Uint8Array(data);
                if (this.trace) {
                    this.traceData.outbound.push(dataBuff);
                }
                const buffer = extendBuffer(dataBuff, this.packetSize);

                if (this.endpointOut) {
                    await this.device.transferOut(
                        this.endpointOut.endpointNumber,
                        buffer
                    );
                } else {
                    await this.device.controlTransferOut(
                        {
                            requestType: 'class',
                            recipient: 'interface',
                            request: 0x09,
                            value: 0x200,
                            index: this.interfaceNumber
                        },
                        buffer
                    );
                }
            };
        }
    }

    /**
     * Call init before any other operation! Main purpose is to instantiate WASM module
     * @return {Promise<void>}
     */
    async Init() {
        if (!this.module) {
            this.module = await loadWasm();
        }
    }

    /**
     * @return {number[]} Returns supported USB vendor IDs.
     */
    get SupportedVendorIDs() {
        return Array.from(this.module.getSupportedVendorIDs());
    }

    /**
     * Opens USB device and inits communication interface.
     * Use **device = await navigator.usb.requestDevice(...)** construction to let user select USB connection.
     * @param {USBDevice} device
     * @return {Promise<void>}
     */
    async Open(device) {
        if (this.device) {
            await this.Close();
        }
        this.device = device;
        if (!this.device) {
            throw new Error("USB device undefined.");
        }
        console.debug(`Opened device: ${this.device.productName} (${this.device.manufacturerName})`);

        await this.device.open();
        // default configuration?
        await this.device.selectConfiguration(1);

        const interfaces = this.device.configuration.interfaces.filter(usbInterface => {
            // default interface class
            return usbInterface.alternates[0].interfaceClass === 0xFF;
        });

        if (!interfaces.length) {
            throw new Error('No valid interfaces found.');
        }

        let selectedInterface = interfaces.find((usbInterface) => usbInterface.alternates[0].endpoints.length > 0);
        if (!selectedInterface) {
            selectedInterface = interfaces[0];
        }
        this.interfaceNumber = selectedInterface.interfaceNumber;

        if (!this.alwaysControlTransfer) {
            const endpoints = selectedInterface.alternates[0].endpoints;

            this.endpointIn = undefined;
            this.endpointOut = undefined;

            for (const endpoint of endpoints) {
                if (endpoint.direction === 'in' && !this.endpointIn) {
                    this.endpointIn = endpoint;
                } else if (endpoint.direction === 'out' && !this.endpointOut) {
                    this.endpointOut = endpoint;
                }
            }
        }

        this.setReadDataHandler();
        this.setWriteDataHandler();

        // todo(mkelnar) read packet size and write to probe object
        return this.device.claimInterface(this.interfaceNumber);
    }

    /**
     * Close currently opened USB device and clean internals.
     * @return {Promise<void>}
     */
    async Close() {
        if (this.device?.opened) {
            await this.device.close();
            console.debug(`Closed device: ${this.device.productName} (${this.device.manufacturerName})`);
        } else {
            console.debug("Device closed somehow");
        }
        this.device = null;
        this.interfaceNumber = undefined;
    }

    /**
     * Reads key information from a USB device.
     * @return {Promise<ProbeInfo>}
     */
    async getProbeInfo() {
        const data = await this.module.getProbeDAPInfo();
        const retVal = new ProbeInfo();
        for (let key in data) {
            if (key in retVal && key in data) {
                if (key === "capabilities") {
                    retVal[key] = new ProbeCapabilities();
                    retVal[key].swd = data[key].swd;
                    retVal[key].jtag = data[key].jtag;
                } else {
                    retVal[key] = data[key];
                }
            }
        }
        return retVal;
    }

    /**
     * Reset target device.
     */
    async Reset() {
        await this.module.reset();
    }

    /**
     * Reset DAP probe. (not sure what's the purpose)
     */
    async ProbeReset() {
        await this.module.probeReset();
    }

    /**
     * Connect to the target debugger
     * @return {Promise<void>}
     */
    async Connect() {
        try {
            await this.module.connect(false);
        } catch (e) {
            console.error(e.message);
        }
    }

    /**
     * Disconnect target debugger
     * @return {Promise<void>}
     */
    async Disconnect() {
        try {
            await this.module.disconnect();
        } catch (e) {
            console.error(e.message);
        }
    }

    /**
     * @param accessPort {boolean} Select access port with true or debug port with false.
     * @param address {number} Register address.
     * @return {Promise<number>} Returns actual value of addressed register.
     */
    async CoreSightRead(accessPort, address) {
        let retVal;
        try {
            retVal = (new Uint32Array([await this.module.coreSightRead(accessPort, address >>> 0)]))[0];
        } catch (e) {
            console.error(e.message);
        }
        return retVal;
    }

    /**
     * @param accessPort {boolean} Select access port with true or debug port with false.
     * @param address {number} Register address.
     * @param data {number} Specify value for addressed register.
     * @return {Promise<void>}
     */
    async CoreSightWrite(accessPort, address, data) {
        try {
            // x >>> 0 is to uint32 conversion
            await this.module.coreSightWrite(accessPort, address >>> 0, data >>> 0);
        } catch (e) {
            console.error(e.message);
        }
    }

    async DPAPjs(justRead = false) {
        let mem_ap_ix = -1;

        const powerControl = async (sysPower) => {
            let req = 0x0F << 8;
            let checkStatus = 0;
            if (sysPower) {
                req |= 0x40 << 24;
                checkStatus = 0x80 << 24;
            } else {
                req |= 0x10 << 24;
                checkStatus = 0x20 << 24;
            }

            await this.CoreSightWrite(false, 0x04, req);  // DP_CTRL_STAT_REG

            let index = 10;
            let ret;
            let succeed = false;
            do {
                await new Promise((resolve) => {
                    setTimeout(resolve, 100);
                });
                ret = await this.CoreSightRead(false, 0x04);
                if ((ret & (0x80 << 24 | 0x20 << 24)) === checkStatus) {
                    succeed = true;
                    break;
                }
            } while (index-- > 0);
            if (!succeed) {
                throw new Error("Failed to control device power");
            }
        };

        const getCoresightAPAddress = (accessPort, address) => {
            if (accessPort > 255) {
                throw new Error("Invalid value of access port");
            }
            return address;
            //return accessPort << 24 | address;  // APPSEL_SHIFT
        };
        const _memRegRead = async (apIx, addr) => {
            await this.CoreSightWrite(true, getCoresightAPAddress(apIx, 0 * 4), 0x22000012);
            await this.CoreSightWrite(true, getCoresightAPAddress(apIx, 1 * 4), addr);
            return this.CoreSightRead(true, getCoresightAPAddress(apIx, 3 * 4));
        };
        const _memRegWrite = async (apIx, addr, data) => {
            await this.CoreSightWrite(true, getCoresightAPAddress(apIx, 0 * 4), 0x22000012);
            await this.CoreSightWrite(true, getCoresightAPAddress(apIx, 1 * 4), addr);
            await this.CoreSightWrite(true, getCoresightAPAddress(apIx, 3 * 4), data);

            await this.CoreSightRead(false, 0x04);
        };
        const getMemAP = async () => {
            if (mem_ap_ix >= 0) {
                return;
            }
            let memAPIX = [0, 1, 3];
            let memAPAddress = 0x20000000;

            for (let item of memAPIX) {
                const idrAddr = getCoresightAPAddress(item, 0xFC);  // IDR_REG
                const idr = await this.CoreSightRead(true, idrAddr);
                const apClass = (idr & 0x1E000) >> 13;

                if (apClass === 8) {
                    let dhcsrReg = await _memRegRead(item, 0xE000EDF0);
                    stdoutHandler("DHCSR register: " + dhcsrReg);
                    await _memRegWrite(item, 0xE000EDF0, 0xA05F0000 | 0x2 | 0x1);

                    let status = false;
                    try {
                        await _memRegRead(item, memAPAddress);
                        status = true;

                    } catch {
                        stderrHandler(">> Read operation on AP" + item + " fails");
                    }
                    await _memRegWrite(item, 0xE000EDF0, 0xA05F0000 | 0x1);
                    await _memRegWrite(item, 0xE000EDF0, 0xA05F0000);
                    if (!status) {
                        continue;
                    }
                    mem_ap_ix = item;
                    stdoutHandler(">> Found memory access port at AP" + item);
                    break;
                }
            }
        };
        const mem_reg_read = async (addr) => {
            await getMemAP();
            return _memRegRead(mem_ap_ix, addr);
        };
        const mem_reg_write = async (addr, data) => {
            await getMemAP();
            return _memRegWrite(mem_ap_ix, addr, data);
        };

        if (justRead) {
            return mem_reg_read(0x2000001c);
        }
        await this.Connect();

        await powerControl(true);
        stdoutHandler("System Power True");
        await powerControl(false);
        stdoutHandler("Debug Power True");

        const testMem = 0x20000000;
        await mem_reg_read(0xE000EDF0);
        await mem_reg_write(0xE000EDF0, 0xA05F0000 | 0x2 | 0x1);
        let status = false;
        try {
            const testValue = await mem_reg_read(testMem);

            await mem_reg_write(testMem, testValue ^ 0xAAAAAAAA);
            const tr = (await mem_reg_read(testMem)) >>> 0;
            await mem_reg_write(testMem, testValue);
            status = (tr === ((testValue ^ 0xAAAAAAAA) >>> 0));
        } catch (e) {
            console.error(e.message);
        } finally {
            await mem_reg_write(0xE000EDF0, 0xA05F0000 | 0x1);
            await mem_reg_write(0xE000EDF0, 0xA05F0000);
        }
        if (!status) {
            throw new Error("Test connection verification failed");
        }
    }

    async fetchData() {
        return this.DPAPjs(true);
    }
}
