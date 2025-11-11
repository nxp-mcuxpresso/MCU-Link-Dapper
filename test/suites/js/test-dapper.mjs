/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license for this file can be found in the LICENSE.txt file included with this distribution
 * or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText
 */

import {after, afterEach, before, describe, it} from "mocha";
import {WebixDapper} from "../../../src/js/webix-dapper.mjs";
import assert from "assert";
import {createRequire} from 'node:module';
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from 'node:path';
import process from "node:process";

globalThis.ddd = path.dirname(import.meta.url);
globalThis.__dirname = path.dirname(path.dirname(
    path.dirname(import.meta.url).substring(os.platform() === "win32" ? 8 : 7))) + "/build/target/webix-dapper";
globalThis.require = createRequire(import.meta.url);

let server;
let browser;

class MockDapper extends WebixDapper {
    inboundIndex = 0;
    outboundIndex = 0;
    traceData = {};
    writeData = [];

    constructor() {
        super();
        this.setStdoutHandler(() => {
            // dummy
        });
        this.setStderrHandler(() => {
            // dummy
        });
    }

    async Open(_device) {
        this.setReadDataHandler(() => {
            return new Uint8Array(this.traceData.inbound[this.inboundIndex++]);
        });
        this.setWriteDataHandler((data) => {
            this.outboundIndex++;
            this.writeData.push([...data]);
        });
    }
}

describe("test-dapper", function () {
    it("test_getSupportedVendorIDs", async () => {
        const dapper = new MockDapper();
        await dapper.Init();
        assert.deepEqual(dapper.SupportedVendorIDs, [0xD28, 0x1fc9]);
    });

    it("test_mcxa153", async () => {
        const data = JSON.parse(fs.readFileSync(process.cwd() + "/test/resources/traces/trace_mcxa153.json").toString());
        assert.ok(Array.isArray(data.inbound));
        assert.ok(Array.isArray(data.outbound));

        const dapper = new MockDapper();
        dapper.traceData = data;
        await dapper.Init();
        await dapper.Open(null);

        assert.deepEqual(
            await dapper.getProbeInfo(),
            {
                boardName: 'FRDM-MCXA153',
                boardVendor: 'NXP',
                capabilities: {
                    jtag: true,
                    swd: true
                },
                firmwareVer: '2.1.1',
                productFwVer: '3.128',
                productId: 'MCU-Link CMSIS-DAP V3.128',
                serialNo: 'WAZHTY5YQ2IUB',
                targetName: 'MCXA153VLH',
                targetVendor: 'NXP',
                vendorId: 'NXP Semiconductors'
            }
        );
        try {
            await dapper.DPAPjs();
        } catch (e) {
            assert.ok(false, e.message);
        }
        assert.equal(dapper.outboundIndex, data.outbound.length);
        assert.deepEqual(dapper.writeData, data.outbound);
    });

    it("trace_mcxn947", async () => {
        const data = JSON.parse(fs.readFileSync(process.cwd() + "/test/resources/traces/trace_mcxn947.json").toString());
        assert.ok(Array.isArray(data.inbound));
        assert.ok(Array.isArray(data.outbound));

        const dapper = new MockDapper();
        dapper.traceData = data;
        await dapper.Init();
        await dapper.Open(null);

        assert.deepEqual(
            await dapper.getProbeInfo(),
            {
                boardName: 'FRDM-MCXN947',
                boardVendor: 'NXP',
                capabilities: {
                    jtag: true,
                    swd: true
                },
                firmwareVer: '2.1.1',
                productFwVer: '3.128',
                productId: 'MCU-Link CMSIS-DAP V3.128',
                serialNo: 'VNNTUE4SZEZCJ',
                targetName: 'MCXN947VDFT',
                targetVendor: 'NXP',
                vendorId: 'NXP Semiconductors'
            }
        );
        try {
            await dapper.DPAPjs();
        } catch (e) {
            assert.ok(false, e.message);
        }
        assert.equal(dapper.outboundIndex, data.outbound.length);
        assert.deepEqual(dapper.writeData, data.outbound);
    });

    it("trace_rt1060_evk", async () => {
        const data = JSON.parse(fs.readFileSync(process.cwd() + "/test/resources/traces/trace_rt1060_evk.json").toString());
        assert.ok(Array.isArray(data.inbound));
        assert.ok(Array.isArray(data.outbound));

        const dapper = new MockDapper();
        dapper.traceData = data;
        await dapper.Init();
        await dapper.Open(null);

        assert.deepEqual(
            await dapper.getProbeInfo(),
            {
                boardName: 'N/A',
                boardVendor: 'N/A',
                capabilities: {
                    jtag: false,
                    swd: true
                },
                firmwareVer: '1.10',
                productFwVer: 'N/A',
                productId: 'N/A',
                serialNo: 'N/A',
                targetName: 'N/A',
                targetVendor: 'N/A',
                vendorId: 'N/A'
            }
        );
        try {
            await dapper.DPAPjs();
        } catch (e) {
            assert.ok(false, e.message);
        }
        assert.equal(dapper.outboundIndex, data.outbound.length);
        assert.deepEqual(dapper.writeData, data.outbound);
    });

    afterEach(async () => {
        if (browser) {
            await browser.close();
        }
    });

    before(() => {
        if (!fs.existsSync("./build/WASM-RUN")) {
            fs.mkdirSync("./build/WASM-RUN", {recursive: true});
        }

        server = http.createServer(($request, $response) => {
            if ($request.url === "/index.html") {
                $response.writeHeader(200, {"Content-Type": "text/html"});
                $response.write(fs.readFileSync(process.cwd() + "/build" + $request.url));
                $response.end();
            } else if ($request.url.startsWith("/") && ($request.url.endsWith(".js") || $request.url.endsWith(".mjs"))) {
                $response.writeHeader(200, {"Content-Type": "application/javascript"});
                $response.write(fs.readFileSync(process.cwd() + "/build" + $request.url));
                $response.end();
            } else if ($request.url.startsWith("/") && $request.url.endsWith(".wasm")) {
                $response.writeHeader(200, {"Content-Type": "application/wasm"});
                $response.write(fs.readFileSync(process.cwd() + "/build" + $request.url));
                $response.end();
            } else if ($request.url.startsWith("/") && $request.url.endsWith(".jpg")) {
                $response.writeHeader(200, {"Content-Type": "image/jpeg"});
                $response.write(fs.readFileSync(process.cwd() + "/build" + $request.url));
                $response.end();
            }
        });
        server.listen(31231);
    });

    after(async () => {
        server.close();
    });
});
