#!/bin/sh

# Copy over the files used by the 2014 assessment, except the
# debfile itself (which includes a copy of most of the files).

THISDIR=$(/usr/bin/dirname $(/usr/bin/which "$0"))

DETER="users.isi.deterlab.net"
PROJDIR="/proj/SAFER/groups/curveball/assessment-2014"

ssh "${DETER}" mkdir -p "${PROJDIR}/scripts"
ssh "${DETER}" mkdir -p "${PROJDIR}/docs"
ssh "${DETER}" mkdir -p "${PROJDIR}/ns"

scp "${THISDIR}"/../scripts/deter/* "${DETER}:${PROJDIR}"/scripts
scp "${THISDIR}"/../scripts/cb-install "${DETER}:${PROJDIR}"/scripts
scp "${THISDIR}"/../scripts/cb-startup-testbed "${DETER}:${PROJDIR}"/scripts

scp "${THISDIR}"/../docs/assessment-2014/*.txt "${DETER}:${PROJDIR}"/docs

scp "${THISDIR}"/../docs/assessment-2014/NS/* "${DETER}:${PROJDIR}"/ns

# patch up permissions, so other curveballers can update the files
# if necessary.

ssh "${DETER}" chmod 775 "${PROJDIR}"
ssh "${DETER}" chmod 775 "${PROJDIR}/docs"
ssh "${DETER}" chmod 775 "${PROJDIR}/ns"
ssh "${DETER}" chmod 775 "${PROJDIR}/scripts"

ssh "${DETER}" chmod 664 "${PROJDIR}/docs/*"
ssh "${DETER}" chmod 664 "${PROJDIR}/ns/*"
ssh "${DETER}" chmod 775 "${PROJDIR}/scripts/*"
