#!/bin/sh

basedir=/usr/libexec

export GIO_EXTRA_MODULES='/usr/lib64/kiran-authentication-service/lib64/gio/modules/'
export GIO_MODULE_DIR='/usr/lib64/kiran-authentication-service/lib64/gio/modules/'
export QT_PLUGIN_PATH="/usr/lib64/kiran-authentication-service/lib64/plugins/qt/plugins/"
exec "$basedir"/kiran-authentication-devices