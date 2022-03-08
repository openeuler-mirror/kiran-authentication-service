project(kiran-authentication-service)
cmake_minimum_required(VERSION 3.5)

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(DEBUG 1)
else()
    set(DEBUG 0)
endif()

include(GNUInstallDirs)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(DATA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/data)
set(MODULE_DIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/kiran-fprint-modules/)
set(SERVICE_NAME "com.kylinsec.Kiran.SystemDaemon.Biometrics")
set(SERVICE_PATH "/com/kylinsec/Kiran/SystemDaemon/Biometrics")
set(SERVICE_INTERFACE "com.kylinsec.Kiran.SystemDaemon.Biometrics")
set(INSTALL_BINDIR ${CMAKE_INSTALL_PREFIX}/libexec)

add_subdirectory(src)
add_subdirectory(data)
add_subdirectory(po)
