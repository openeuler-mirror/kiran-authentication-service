set(VIRTUAL_CZHT_DRIVER_INSTALL_DIR ${VIRTUAL_DRIVERS_INSTALL_DIR}/czht)

set(TARGET_NAME czht)
set(TARGET_CODE_NAME czht-code)

find_package(Qt5 REQUIRED COMPONENTS DBus Core)

add_library(${TARGET_NAME} SHARED czht-driver.cpp czht-driver.h czht-error.h)
add_library(${TARGET_CODE_NAME} SHARED czht-code-driver.cpp czht-code-driver.h
                                       czht-error.h)

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
          ${PROJECT_BINARY_DIR}
          ${PROJECT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR}/include
          ${PROJECT_SOURCE_DIR}/src/device-manager/driver
          ${KLOG_QT5_INCLUDE_DIRS})

target_include_directories(
  ${TARGET_CODE_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
          ${PROJECT_BINARY_DIR}
          ${PROJECT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR}/include
          ${PROJECT_SOURCE_DIR}/src/device-manager/driver
          ${KLOG_QT5_INCLUDE_DIRS})

target_link_libraries(${TARGET_NAME} PRIVATE Qt5::Core Qt5::DBus
                                             ${KLOG_QT5_LIBRARIES})

target_link_libraries(${TARGET_CODE_NAME} PRIVATE Qt5::Core Qt5::DBus
                                                  ${KLOG_QT5_LIBRARIES})

install(TARGETS ${TARGET_NAME} DESTINATION ${VIRTUAL_CZHT_DRIVER_INSTALL_DIR})
install(TARGETS ${TARGET_CODE_NAME}
        DESTINATION ${VIRTUAL_CZHT_DRIVER_INSTALL_DIR})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.ini
        DESTINATION ${VIRTUAL_CZHT_DRIVER_INSTALL_DIR})

add_subdirectory(tools)
