/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license for this file can be found in the LICENSE.txt file included with this distribution
 * or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText
 */
import archiver from "archiver";
import commonjs from '@rollup/plugin-commonjs';
import copy from "rollup-plugin-copy";
import del from "rollup-plugin-delete";
import fs from "fs";
import {nodeResolve} from '@rollup/plugin-node-resolve';
import terser from "@rollup/plugin-terser";

async function createPkg(pkgDir) {
    const pkg = JSON.parse(fs.readFileSync("package.json", "utf-8"));
    const output = fs.createWriteStream(`build/${pkgDir}-${pkg.version.replace(/\./gm, "-")}.zip`);
    const archive = archiver("zip");

    output.on('close', () => {
        console.log("archive " + output.path + " constructed");
    });
    output.on('end', () => {
        console.log("finished");
    });
    archive.on('warning', (err) => {
        if (err.code !== "ENOENT") {
            throw err;
        }
    });
    archive.on("error", (err) => {
        throw err;
    });
    archive.pipe(output);

    archive.directory(`build/target/${pkgDir}`, pkgDir, null);
    return archive.finalize();
}

export default [
    {
        input: ["src/js/webix-dapper.mjs"],
        // suppress eval warnings because emscripten needs DYNAMIC_EXECUTION=1 in current configuration
        onwarn(warning, warn) {
            if (warning.code === 'EVAL') {
                return;
            }
            warn(warning);
        },
        output: [
            {
                dir: "build/target/webix-dapper-js",
                format: "esm",
                sourcemap: false
            }
        ],
        plugins: [
            del({targets: "build/target"}),
            nodeResolve(),
            commonjs(),
            terser(),
            // copy JS
            copy({
                targets: [
                    {
                        src: "build/build_wasm/webix-*.wasm",
                        dest: "build/target/webix-dapper-js"
                    },
                    {
                        src: "LICENSE.txt",
                        dest: "build/target/webix-dapper-js"
                    }
                ]
            }),
            // copy Python
            copy({
                targets: [
                    {
                        src: ["src/python/dapper/*.py"],
                        dest: "build/target/webix-dapper-py/dapper"
                    },
                    {
                        src: ["src/python/dapper/core/*.py"],
                        dest: "build/target/webix-dapper-py/dapper/core"
                    },
                    {
                        src: ["src/python/dapper/interfaces/*.py"],
                        dest: "build/target/webix-dapper-py/dapper/interfaces"
                    },
                    {
                        src: ["src/python/requirements.txt", "src/python/setup.py"],
                        dest: "build/target/webix-dapper-py"
                    },
                    {
                        src: "build/build_wasm/webix-*.wasm",
                        dest: "build/target/webix-dapper-py/dapper"
                    },
                    {
                        src: "LICENSE.txt",
                        dest: "build/target/webix-dapper-py"
                    }
                ]
            }),
            {
                name: "pack-js",
                async writeBundle() {
                    await createPkg("webix-dapper-js");
                }
            },
            {
                name: "pack-py",
                async writeBundle() {
                    await createPkg("webix-dapper-py");
                }
            },
            // prepare PKG for scans
            copy({
                hook: "writeBundle",
                targets: [
                    {
                        src: ["bin", "scripts", "src", "test"],
                        dest: "build/target/webix-dapper-src"
                    },
                    {
                        src: ["build/target/webix-dapper-js", "build/target/webix-dapper-py"],
                        dest: "build/target/webix-dapper-src/build/target"
                    },
                    {
                        src: ["CMakeLists.txt", "LICENSE.txt", "package.json", "package.conf.jsonp",
                            "pyproject.toml", "README.md", "SW-Content-Register.txt"],
                        dest: "build/target/webix-dapper-src"
                    }
                ]
            }),
            {
                name: "pack-bd",
                async closeBundle() {
                    await createPkg("webix-dapper-src");
                }
            }
        ]
    }
];
