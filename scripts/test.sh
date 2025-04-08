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
mkdir -p build/reports/unit/python
pytest -v --junitxml=build/reports/unit/python/py-junit.xml test/suites/python/test*.py || exit 1

if command - v codecheck >/dev/null 2>&1; then
  codecheck --disable-check PYTEST --parent-branch main || exit 1
fi

echo "Tests done"
