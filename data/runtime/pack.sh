#!/bin/bash

buildroot=$1
sourcedir=$2
lib64_installdir=${buildroot}/usr/lib64/kiran-authentication-service/lib64
# plugins_installdir=${lib64_installdir}/plugins
# qtplugins_installdir=${plugins_installdir}/qt/plugins/

# real_deps_installdir=/usr/lib64/kiran-authentication-service/lib64

mkdir -p ${lib64_installdir}


set -x
DEPS_PATH_LIST=$(ldconfig -p | grep -oP '/[^ ]*')

for libdep in $(cat ${sourcedir}/data/runtime/lib64); do
    dep_path=$(echo $DEPS_PATH_LIST | tr ' ' '\n' | grep $libdep || echo "")
    if [ -z "$dep_path" ];then
        echo "WARNING: miss libdep: ${libdep}"
            continue;
    fi
    cp $dep_path ${lib64_installdir}
done

# set -x
# QT_PLUGINS_PATH="/usr/lib64/qt5/plugins/"
# cp -rp ${QT_PLUGINS_PATH}/* ${qtplugins_installdir}/

# GIO_MODULES_PATH="/usr/lib64/gio/modules/"
# cp -rp ${GIO_MODULES_PATH}/* ${gio_modules_installdir}/