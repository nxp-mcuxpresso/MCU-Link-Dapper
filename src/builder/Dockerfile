 #/* ********************************************************************************************************* *
 # *
 # * Copyright 2024 NXP
 # * Copyright 2025 Oidis
 # *
 # * SPDX-License-Identifier: BSD-3-Clause
 # * The BSD-3-Clause license for this file can be found in the LICENSE.txt file included with this distribution
 # * or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText
 # *
 # * ********************************************************************************************************* */

FROM nxpwebix/webix-dapper-base:2024.1.0
LABEL org.opencontainers.image.authors="michal@oidis.org"

WORKDIR "/var/webix"
COPY build.sh build.sh
RUN sed -i 's/\r//g' build.sh
RUN chmod +x build.sh

CMD ["./build.sh"]
