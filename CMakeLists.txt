cmake_minimum_required(VERSION 3.0)

project(kiran-authentication-service VERSION 2.6)

include(GNUInstallDirs)
set(KAS_INSTALL_DATADIR ${CMAKE_INSTALL_FULL_DATADIR}/${PROJECT_NAME})
set(KAS_INSTALL_INCLUDE ${CMAKE_INSTALL_FULL_INCLUDEDIR}/${PROJECT_NAME})
set(KAS_INSTALL_TRANSLATIONDIR ${KAS_INSTALL_DATADIR}/translations)
set(KAS_INSTALL_SYSCONFDIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME})
set(KAS_INSTALL_DEP_LIBDIR ${CMAKE_INSTALL_FULL_LIBDIR}/${PROJECT_NAME}/lib64)

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

configure_file(config.h.in ${PROJECT_BINARY_DIR}/config.h)

file(GLOB_RECURSE COMMON_CPP_FILES ${PROJECT_SOURCE_DIR}/lib/*.cpp)

add_subdirectory(data)
add_subdirectory(lib)
add_subdirectory(src)

install(FILES include/kas-authentication-i.h
        DESTINATION ${KAS_INSTALL_INCLUDE}/)

# 用于适配旧系统升级了gcc的情况
execute_process(
  COMMAND sh -c "ldconfig -p | grep libstdc++ | awk '{print \$NF}' | head -1"
  OUTPUT_VARIABLE DEP_PATH
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(DEP_PATH)
  message(STATUS "DEP_PATH: ${DEP_PATH}")
  install(FILES ${DEP_PATH} DESTINATION ${KAS_INSTALL_DEP_LIBDIR})
endif()
