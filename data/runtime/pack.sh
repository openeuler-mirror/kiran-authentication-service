#!/bin/bash

buildroot=$1
sourcedir=$2
lib64_installdir=${buildroot}/usr/lib64/kiran-authentication-service/lib64
plugins_installdir=${lib64_installdir}/plugins
qtplugins_installdir=${plugins_installdir}/qt/plugins/
gio_modules_installdir=${lib64_installdir}/gio/modules

mkdir -p ${lib64_installdir}
mkdir -p ${qtplugins_installdir}
mkdir -p ${gio_modules_installdir}


set +x
DEPS_PATH_LIST=$(ldconfig -p | grep -oP '/[^ ]*')
for libdep in $(grep -v "^#" ${sourcedir}/data/runtime/lib64); do
    # 使用更精确的匹配：匹配以库名开头的路径，只取第一个匹配
    dep_path=$(echo "$DEPS_PATH_LIST" | tr ' ' '\n' | grep "/${libdep}\." | head -1)
    if [ -z "$dep_path" ];then
        echo "WARNING: miss libdep: ${libdep}"
        continue;
    fi
    
    # 获取实际文件路径（如果是符号链接，跟随到实际文件）
    real_path=$(readlink -f "$dep_path")
    if [ -z "$real_path" ] || [ ! -f "$real_path" ]; then
        echo "WARNING: cannot resolve path for ${libdep}: ${dep_path}"
        continue;
    fi
    
    real_name=$(basename "$real_path")
    target_file="${lib64_installdir}/${real_name}"
    
    # 拷贝实际文件
    if [ ! -f "$target_file" ]; then
        echo "cp $real_path -> ${target_file}"
        cp -p "$real_path" "$target_file"
    fi
    
    # 如果源路径是符号链接，创建对应的链接
    if [ -L "$dep_path" ]; then
        link_name=$(basename "$dep_path")
        target_link="${lib64_installdir}/${link_name}"
        if [ ! -e "$target_link" ]; then
            echo "ln -sf ${real_name} -> ${target_link}"
            ln -sf "$real_name" "$target_link"
        fi
    fi
done

set -x
QT_PLUGINS_PATH="/usr/lib64/qt5/plugins/"
cp -rp ${QT_PLUGINS_PATH}/* ${qtplugins_installdir}/

GIO_MODULES_PATH="/usr/lib64/gio/modules/"
cp -rp ${GIO_MODULES_PATH}/* ${gio_modules_installdir}/