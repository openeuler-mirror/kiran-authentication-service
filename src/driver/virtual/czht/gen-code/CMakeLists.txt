set(TARGET_NAME kiran-auth-code-request)

find_package(Qt5 REQUIRED COMPONENTS DBus Widgets)

set(TARGET_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/gen-code-dialog.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/gen-code-dialog.h
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp ${CZHT_INCLUDE_DIRS}/czht-define.h)

# 添加资源文件
qt5_add_resources(RESOURCE_FILES ${PROJECT_SOURCE_DIR}/resources/resources.qrc)

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

add_executable(${TARGET_NAME} ${TARGET_SOURCES} ${RESOURCE_FILES} ${QM_FILES})

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_BINARY_DIR}
          ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include
          ${KLOG_QT5_INCLUDE_DIRS} ${CZHT_INCLUDE_DIRS})

target_link_libraries(${TARGET_NAME} PRIVATE Qt5::Widgets Qt5::DBus
                                             ${KLOG_QT5_LIBRARIES})

install(FILES ${QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
