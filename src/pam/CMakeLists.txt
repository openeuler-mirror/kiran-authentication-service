file(GLOB_RECURSE H_FILES ./*.h)
file(GLOB_RECURSE CPP_FILES ./*.cpp)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.xml
  PROPERTIES CLASSNAME AuthManagerProxy NO_NAMESPACE true)

qt5_add_dbus_interface(
  AUTH_MANAGER_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.xml
  auth_manager_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.Session.xml
  PROPERTIES CLASSNAME AuthSessionProxy NO_NAMESPACE true)

qt5_add_dbus_interface(
  AUTH_SESSION_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.Session.xml
  auth_session_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.User.xml
  PROPERTIES CLASSNAME AuthUserProxy NO_NAMESPACE true)

qt5_add_dbus_interface(
  AUTH_USER_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.User.xml
  auth_user_proxy)

set(TARGET_NAME pam_kiran_authentication)

configure_file(config-pam.h.in ${CMAKE_CURRENT_BINARY_DIR}/config-pam.h)

# 定义翻译源文件列表
set(QM_FILES "")

foreach(LANG ${LANGUAGES})
  # ts 文件路径
  set(TS_FILE "${PROJECT_SOURCE_DIR}/translations/${TARGET_NAME}.${LANG}.ts")

  # 执行 lupdate 更新 ts 文件
  execute_process(COMMAND lupdate-qt5 -no-obsolete ${H_FILES} ${CPP_FILES}
                          ${COMMON_CPP_FILES} -ts ${TS_FILE})

  # https://bugreports.qt.io/browse/QTBUG-64317 5.9.4以下生成的qm文件不带${LANG}后缀
  # qt5_add_translation(QM_FILE ${TS_FILE})
  set(QM_FILE "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.${LANG}.qm")
  # 执行 lrelease 生成qm文件
  execute_process(COMMAND lrelease ${TS_FILE} -qm ${QM_FILE})
  list(APPEND QM_FILES ${QM_FILE})
  message(STATUS "QM_FILE: ${QM_FILE}")
endforeach()

add_library(
  ${TARGET_NAME} SHARED
  ${H_FILES} ${CPP_FILES} ${AUTH_MANAGER_INTERFACE_SRCS}
  ${AUTH_SESSION_INTERFACE_SRCS} ${AUTH_USER_INTERFACE_SRCS} ${QM_FILE})

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR}/include ${KLOG_QT5_INCLUDE_DIRS}
          ${PAM_INCLUDE_DIRS})

target_link_libraries(
  ${TARGET_NAME} PRIVATE ${KLOG_QT5_LIBRARIES} ${PAM_LIBRARIES} Qt5::Core
                         Qt5::DBus common)

set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")

install(FILES ${QM_FILE} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
install(TARGETS ${TARGET_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/security/)
