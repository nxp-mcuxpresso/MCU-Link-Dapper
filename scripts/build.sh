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

if [[ ! -f "$projectRoot/package.json" ]]; then
  echo "Incorrect project root."
  exit 1
fi

cd "$projectRoot"/src/builder || exit 1

docker-compose -f builder.yml up --force-recreate --renew-anon-volumes --build --remove-orphans --abort-on-container-exit || exit 1
