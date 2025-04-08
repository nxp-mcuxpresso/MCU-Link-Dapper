# MCU-Link-Dapper

> Module for application to target communication over CMSIS-DAP

## Requirements

[Docker engine](https://docs.docker.com/engine/install/ubuntu/) is needed for WASM module build via emscripten.

[Node.js 18.*](https://nodejs.org/download/release/v14.18.0/) version for development, testing and release process.
Setup "Node interpreter" path in CLion preferences "Languages & Frameworks | Node.js | Node interpreter". Or add Node.js folder to search path if calling npm scripts from terminal.

[Oidis builder](https://gitlab.com/oidis/io-oidis-builder) - to deploy released package to nexus server or for build image base preparation/deploy.
Could be installed with [updater scripts](https://gitlab.com/oidis/io-oidis-ops/-/tree/main/source/scripts?ref_type=heads).

## Project Build

This project ecosystem is IDE independent and could be build/tested or even released directly from command line. Most of the common
tasks depends only on Node.js with NPM and Docker engine (or Podman). While Node.js with NPM take care about project tasks execution and system preparation then Docker/Podman is for WASM code build in sandboxed environment.

These are general NPM tasks:
- **install** - installs NPM dependencies and build wasm in docker environment
- **test** - runs prepared tests for both envs (browser, nodejs) by default
- **build** - builds wasm module in docker environment and prepare build/target folder with test data (for runtime test)
- **watch** - starts rollup server in build/target directory, so open link from stdout to load page. Modifications of test files will be automatically reloaded in browser once file is saved (wasm code needs build and manual reload in browser).
- **release** - prepare package for distribution
- **lint** - explicitly run eslint task

> **Note**: If "npm test" is called manually then do not forget to define environment variable **export/set NODE_OPTIONS="--no-experimental-fetch"**. Only install and test tasks should be called as "npm task-name" rest of them needs to be called ad "npm run task-name".

> **Info**: It is not necessary to stop "watch" task during development, let it run and simply modify files project files and your browser will be automatically reloaded with the newest version.

All of mentioned NPM tasks are configured as IDEA Run profiles. Together with them there are other profiles for development in Jetbrains CLion.
Default Run/Debug configurations are saved in project config and will be enabled right after "Node interpreter" property will be set in preferences:
- Unit test (npm test)
- Browser test - run "npm watch" and open link in terminal or open build/target/index.html after first successful npm install (open it in Idea, etc.)

Inclusive part of "Unit test" and "Run" configuration is "build" to force apply the latest changes into build relicts.


## Project Release

When WASM package needs to be created then use "npm run release" task and package will be generated in ./build folder with version name postfix generated from **package.version** variable.
Generated archive could be sent to destination manually or with nexus deploy task in Oidis builder.

```shell
# <profile> could be dev|eap|prod
oidis nexus:<profile>
```

However, to accomplish that deploy you will need to configure deployment credentials (if nexus repository is not set as anonymous write).
So you will need credentials (when using access token instead of password is strongly recommended) with write permissions.

1) set it in project: create private.conf.jsonp with
    ```javascript
    Io.Oidis.Builder.DAO.Resources.Data({
        nexusConfig: {
            user: "<user>",
            pass: "<token>",
            // or use base64 encoded basic credential form
            user: "<base64(user + ':' + token)>"
        }
    });
    ```

2) or set this config into OidisBuilder.config.jsonp (exactly the same form as in previous point) but location is in folder where builder is located
    ```shell
    # get builder path with
    oidis --path
    ```

3) first two points are useful especially for automation or permanent use. If it is on time request for upload then simply call "oidis nexus:<profile>" command and terminal will ask for user, pass or combined form.

> **Note**: Destination for deployment is specified in package.conf.jsonp.

## Project Advanced Setup
> **Important**: Setup below is actively used and tested only on Posix! Windows is theoretically possible but could be complicated to set up build tools (native or emscripten)

There is also possibility to set up everything manually directly on host system to build native version (for easier debugging of native code) or with Emscripten.
With this setup you can ignore Docker/Podman dependency. Instead of that you will need to take care about several others which are prepared for build in docker image.
* [Emscripten](https://emscripten.org/docs/getting_started/downloads.html) - version 3.1.54 is currently used
* CMake, gcc/clang, clang-format v17, clang-tidy v17, python,... (validated only on linux/mac, windows may need another tools/dependencies - start with emscripten documentation and apply it)


### Emscripten

Required only for build with Emscripten toolchain, ignore this step for Native build.
Installation of emscripten is quite easy and works well according to [official instructions](https://emscripten.org/docs/getting_started/downloads.html).

Remember location of emscripten repository root (emsdk directory) because it will be needed in later setup.

```shell
source <emsdk-path>/emsdk_env.sh
emsdk install 3.1.54
emsdk activate 3.1.54
```

### Update CMake Settings and CLion Integration

> **Note**: Older version needs to have "-DNATIVE_BUILD=1" option defined too, but currently it is not necessary because it is selected based on used toolchain (default is native).
> However if something happen in your local environment you can enforce it.

1) Native build

   Now you can use already prepared Run config in CLion "webix-dapper-wasm".

2) Emscripten

   There is no such toolchain available in CLion thus it needs to be created. Open "Build, Execution, Deployment | Toolchains" and
   create new toolchain "Emscripten" and click on "Add environment" and then "from file". Modify settings as below
    ```
    Environment file: <emsdk-path>/emsdk_env.sh
    C Compiler: emcc
    C++ Compiler: em++
    ```
   Now you can crete new profile in "Build, Execution, Deployment | CMake" and select "Toolchain: Emscripten". Now it is necessary to add
   Emscripten toolchain file into CMake profile options
    ```
    -DCMAKE_TOOLCHAIN_FILE=<emsdk-path>/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake
    ```

When everything is set properly then after CMake reload it should load two profiles in CLion -> CMake window (Default and Emscripten).
In such case and when Run/Debug configuration is selected to any CMake Application (webix-dapper-wasm) you can CLion will show profile dropdown selector.

Select profile Default/Emscripten and happy coding.

> **Note**: Debugger work correctly only with Native build. Emscripten profile is only building wasm libraries and js-glue so for debugging you will need "npm run watch".

## Code formatting
> requires [clang-format](https://clang.llvm.org/docs/ClangFormat.html) to be installed on machine (version 17+)

It is highly recommended to use CLion IDE or any other capable and relevant IDE with code formatting feature. Import both
**.clang-tidy** and **.clang-format** configurations in IDE settings if not loaded automatically. After that you will
be able to review and fix code formatting directly in IDE. There is prepared script to run clang-tidy formatter.

You can call formatter manually from commandline with prepared script. (Only for posix).
```shell
./scripts/lint.sh
```

> This script is called during native code build process, so development on Win platform is covered indirectly within build container.

Second part of formatting is javascript. We are using ESLint for this task and you can run it with command below. Meanwhile, it is executed automatically during release package preparation.

```shell
npm run lint
```

## Python profiling
Install package scalene over pip.
```shell
pip install scalene
```

Successful execution of profiler depends on proper environment setup, so add src and test folders to python path.
```shell
export PYTHONPATH=<dapper-dir>/src:<dapper-dir>/test:$PYTHONPATH
```

Now you can run profiling.
```shell
scalene src/python/run.py
# or
scalene test/suites/python/test_wasm_api.py 
```

The cProfile could be used too, simply modify code which you want to profile (whole script is also possible) with something like that.
```python
import cProfile
import os
# .. code ..
cProfile.run('MockDapper.dpap_test(dap)', os.path.abspath(os.path.dirname(__file__)) + "/profiling.prof")
# MockDapper.dpap_test(dap)
```

Now to read the data you will need some UI interpreter (it is possible to print data into stdout with ignoring the .run() second argument).
```shell
pip install snakeviz
# and run
snakeviz <path-to-prof-file>
```

## License

This software has been owned or controlled by NXP Semiconductors.
Now this fork of the original software is owned or controlled by Oidis organisation.

Use of this software is governed by the BSD-3-Clause License distributed with this material.

See the `LICENSE.txt` file distributed for more details.

---
Copyright 2023-2025 [NXP](http://nxp.com/)
Copyright 2025 [Oidis](https://oidis.org/)
