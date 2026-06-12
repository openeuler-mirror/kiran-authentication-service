set(TARGET_NAME kiran-code)

find_package(Qt5 REQUIRED COMPONENTS DBus Core)

set(KIRAN_CODE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/kiran-code-driver.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/kiran-code-driver.h
    ${KIRAN_INCLUDE_DIRS}/kiran-define.h
    ${KIRAN_INCLUDE_DIRS}/kiran-driver-base.cpp
    ${KIRAN_INCLUDE_DIRS}/kiran-driver-base.h)

# 定义翻译源文件列表
set(QM_FILES "")

foreach(LANG ${LANGUAGES})
  set(TS_FILE "${PROJECT_SOURCE_DIR}/translations/${TARGET_NAME}.${LANG}.ts")
  execute_process(COMMAND lupdate-qt5 -no-obsolete ${KIRAN_CODE_SOURCES} -ts
                          ${TS_FILE})
  set(QM_FILE "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.${LANG}.qm")
  execute_process(COMMAND lrelease-qt5 ${TS_FILE} -qm ${QM_FILE})
  list(APPEND QM_FILES ${QM_FILE})
  message(STATUS "QM_FILE: ${QM_FILE}")
endforeach()

add_library(${TARGET_NAME} SHARED ${KIRAN_CODE_SOURCES} ${QM_FILES})

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
          ${PROJECT_BINARY_DIR}
          ${PROJECT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR}/include
          ${PROJECT_SOURCE_DIR}/src/device/driver
          ${KLOG_QT5_INCLUDE_DIRS}
          ${KIRAN_INCLUDE_DIRS})

target_link_libraries(${TARGET_NAME} PRIVATE Qt5::Core Qt5::DBus
                                             ${KLOG_QT5_LIBRARIES})

install(TARGETS ${TARGET_NAME} DESTINATION ${VIRTUAL_KIRAN_DRIVER_INSTALL_DIR})
install(FILES ${QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
