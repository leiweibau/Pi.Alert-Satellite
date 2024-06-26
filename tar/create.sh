#!/bin/sh

PIALERT_DEV_PATH=../../
cd $PIALERT_DEV_PATH
pwd
PIALERT_VERSION=`awk '$1=="VERSION" { print $3 }' pialert_satellite/config/version.conf | tr -d \'`

# ------------------------------------------------------------------------------
ls -l pialert_satellite/tar/pialert_satellite*.tar
tar tvf pialert_satellite/tar/pialert_satellite_latest.tar | wc -l
rm pialert_satellite/tar/pialert_satellite*.tar

# ------------------------------------------------------------------------------
tar cvf pialert_satellite/tar/pialert_satellite_latest.tar --no-mac-metadata --no-xattrs --exclude="pialert_satellite/tar" --exclude="pialert_satellite/.git" --exclude="pialert_satellite/.github" --exclude=".gitignore" --exclude=".DS_Store" pialert_satellite | wc -l

#ln -s pialert_$PIALERT_VERSION.tar pialert/package/pialert_latest.tar
#ls -l pialert/package/pialert*.tar
