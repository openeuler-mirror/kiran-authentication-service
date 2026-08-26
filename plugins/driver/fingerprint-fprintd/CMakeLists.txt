# 基于 fprintd 的指纹驱动插件（D-Bus net.reactivated.Fprint，不链接 libfprint.so）
set(TARGET_NAME kiran-fingerprint-fprintd)

set(CMAKE_AUTOMOC ON)

set(TARGET_SOURCES
    fprintd-fingerprint-driver.cpp
    fprintd-fingerprint-driver.h)

add_library(${TARGET_NAME} MODULE ${TARGET_SOURCES})

target_include_directories(${TARGET_NAME} PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR})

target_link_libraries(${TARGET_NAME} PRIVATE
    Qt5::Core
    Qt5::DBus)

install(TARGETS ${TARGET_NAME}
        LIBRARY DESTINATION ${KAS_AUTH_DRIVERSDIR})
