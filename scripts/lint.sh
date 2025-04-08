#!/usr/bin/env bash
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

sourceFile="${BASH_SOURCE[0]}"
while [ -h "$sourceFile" ]; do
  sourceLink="$(readlink "$sourceFile")"
  if [[ $sourceLink == /* ]]; then
    sourceFile="$sourceLink"
  else
    sourceDir="$(dirname "$sourceFile")"
    sourceFile="$sourceDir/$sourceLink"
  fi
done
projectRoot="$(cd -P "$(dirname "$sourceFile")/../" && pwd)"

if [[ ! -f "$projectRoot/CMakeLists.txt" ]]; then
  echo "Incorrect project root."
  exit 1
fi

echo "> lint WASM"
# shellcheck disable=SC2044
for i in $(find ./src ./test -name '*.hpp' -o -name '*.h' -o -name '*.cpp' -o -name '*.c' -o -name '*.cc'); do
  clang-format --style="file" --verbose -Werror -i "$i"
done

echo "> lint JS"
eslint . --fix --max-warnings 0 || exit 1

echo "> lint Python"

if [ ! -d "venv" ]; then
  python3 -m venv venv
fi

source venv/bin/activate
pip3 install -U pip
pip3 install -r requirements.txt
pip3 install -r src/python/requirements.txt

# shellcheck disable=SC2155
export PYTHONPATH=$(pwd):$(pwd)/src:$(pwd)/test
export PYTHONUNBUFFERED=1
pylint ./src ./test || exit 1

if command - v codecheck >/dev/null 2>&1; then
  codecheck --fix --disable-check PYTEST --parent-branch main || exit 1
fi

echo "Lint done"
