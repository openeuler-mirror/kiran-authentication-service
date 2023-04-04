cmake_minimum_required(VERSION 3.0)

project(kiran-authentication-service VERSION 2.5)

include(GNUInstallDirs)
set(KAS_INSTALL_DATADIR ${CMAKE_INSTALL_FULL_DATADIR}/${PROJECT_NAME})
set(KAS_INSTALL_INCLUDE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/${PROJECT_NAME})
set(KAS_INSTALL_TRANSLATIONDIR ${KAS_INSTALL_DATADIR}/translations)
set(KAS_INSTALL_SYSCONFDIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED on)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(PkgConfig REQUIRED)
find_package(Qt5 COMPONENTS Core DBus LinguistTools)

pkg_search_module(KLOG_QT5 REQUIRED klog-qt5)
pkg_search_module(SYSTEMD REQUIRED systemd)
pkg_search_module(KIRAN_CC_DAEMON REQUIRED kiran-cc-daemon)
pkg_search_module(PAM REQUIRED pam)
pkg_search_module(LIBSYSTEMD REQUIRED libsystemd)

configure_file(config.h.in ${PROJECT_BINARY_DIR}/config.h)

add_subdirectory(data)
add_subdirectory(src)

install(FILES include/kas-authentication-i.h DESTINATION ${KAS_INSTALL_INCLUDE}/)