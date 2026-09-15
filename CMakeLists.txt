cmake_minimum_required(VERSION 3.0...${CMAKE_VERSION})

project(kiran-authentication-service VERSION 2.6)

include(GNUInstallDirs)

set(KAS_INSTALL_DATADIR ${CMAKE_INSTALL_FULL_DATADIR}/${PROJECT_NAME})
set(KAS_INSTALL_INCLUDE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/${PROJECT_NAME})
set(KAS_INSTALL_TRANSLATIONDIR ${KAS_INSTALL_DATADIR}/translations)
set(KAS_INSTALL_SYSCONFDIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME})
set(KAS_INSTALL_DEP_LIBDIR ${CMAKE_INSTALL_FULL_LIBDIR}/${PROJECT_NAME}/lib64)
set(KAS_AUTH_DRIVERSDIR ${CMAKE_INSTALL_FULL_LIBDIR}/${PROJECT_NAME}/drivers)
set(SOFT_DRIVERS_INSTALL_DIR ${KAS_AUTH_DRIVERSDIR}/soft)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED on)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# 定义支持的语言列表
set(LANGUAGES zh_CN) # 可以添加更多语言  # set(LANGUAGES zh_CN bo_CN ug_CN mn_MN ky_KG
                     # kk_KZ)

find_package(PkgConfig REQUIRED)
find_package(Qt5 COMPONENTS Core DBus Sql Concurrent LinguistTools)

pkg_search_module(KLOG_QT5 REQUIRED klog-qt5)
pkg_search_module(PAM QUIET pam)
if(NOT DEFINED ${PAM_FOUND})
  set(PAM_INCLUDE_DIRS /usr/include/security)
  set(PAM_LIBRARIES pam)
endif()

# PAM 模块必须装在 PAM 实际扫描的固定目录（因发行版/架构而异），
# 与 KAS_AUTH_DRIVERSDIR 一致：优先探测目标机真实目录，打包可用
# -DPAM_SECURITY_DIR=<dir> 覆盖。
#   CentOS/openEuler -> /lib64/security；sw 等 -> /lib/security；
#   Debian/Ubuntu multiarch -> /lib/<arch>/security。
if(DEFINED PAM_SECURITY_DIR)
  set(KAS_INSTALL_PAM_MODULEDIR "${PAM_SECURITY_DIR}")
elseif(CMAKE_LIBRARY_ARCHITECTURE AND
       IS_DIRECTORY "/lib/${CMAKE_LIBRARY_ARCHITECTURE}/security")
  set(KAS_INSTALL_PAM_MODULEDIR "/lib/${CMAKE_LIBRARY_ARCHITECTURE}/security")
elseif(IS_DIRECTORY "/lib64/security")
  set(KAS_INSTALL_PAM_MODULEDIR "/lib64/security")
elseif(IS_DIRECTORY "/lib/security")
  set(KAS_INSTALL_PAM_MODULEDIR "/lib/security")
else()
  set(KAS_INSTALL_PAM_MODULEDIR "${CMAKE_INSTALL_FULL_LIBDIR}/security")
endif()

configure_file(config.h.in ${PROJECT_BINARY_DIR}/config.h)

file(GLOB_RECURSE COMMON_CPP_FILES ${PROJECT_SOURCE_DIR}/lib/*.cpp)

add_subdirectory(data)
add_subdirectory(lib)
add_subdirectory(src)

add_subdirectory(plugins/pam)
add_subdirectory(plugins/driver)

install(FILES include/kas-authentication-i.h
        DESTINATION ${KAS_INSTALL_INCLUDE}/)
