set(TARGET_NAME czht-code)

find_package(Qt5 REQUIRED COMPONENTS DBus Core)

set(TARGET_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/czht-code-driver.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/czht-code-driver.h
    ${CZHT_INCLUDE_DIRS}/czht-define.h)

# 定义翻译源文件列表
set(QM_FILES "")

foreach(LANG ${LANGUAGES})
  # ts 文件路径
  set(TS_FILE "${PROJECT_SOURCE_DIR}/translations/${TARGET_NAME}.${LANG}.ts")

  # 执行 lupdate 更新 ts 文件
  execute_process(COMMAND lupdate-qt5 -no-obsolete ${TARGET_SOURCES} -ts
                          ${TS_FILE})

  # https://bugreports.qt.io/browse/QTBUG-64317 5.9.4以下生成的qm文件不带${LANG}后缀
  # qt5_add_translation(QM_FILE ${TS_FILE})
  set(QM_FILE "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.${LANG}.qm")
  # 执行 lrelease 生成qm文件
  execute_process(COMMAND lrelease-qt5 ${TS_FILE} -qm ${QM_FILE})
  list(APPEND QM_FILES ${QM_FILE})
  message(STATUS "QM_FILE: ${QM_FILE}")
endforeach()

add_library(${TARGET_NAME} SHARED ${TARGET_SOURCES} ${QM_FILES})

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
          ${PROJECT_BINARY_DIR}
          ${PROJECT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR}/include
          ${PROJECT_SOURCE_DIR}/src/device-manager/driver
          ${KLOG_QT5_INCLUDE_DIRS}
          ${CZHT_INCLUDE_DIRS})

target_link_libraries(${TARGET_NAME} PRIVATE Qt5::Core Qt5::DBus
                                             ${KLOG_QT5_LIBRARIES})

install(TARGETS ${TARGET_NAME} DESTINATION ${VIRTUAL_CZHT_DRIVER_INSTALL_DIR})
install(FILES ${QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
