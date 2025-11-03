file(GLOB_RECURSE H_FILES ./*.h)
file(GLOB_RECURSE CPP_FILES ./*.cpp)

qt5_add_dbus_adaptor(
  AUTH_MANAGER_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.xml
  ${CMAKE_SOURCE_DIR}/src/daemon/auth-manager.h
  Kiran::AuthManager
  auth_manager_adaptor
  AuthManagerAdaptor)

qt5_add_dbus_adaptor(
  AUTH_SESSION_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.Session.xml
  ${CMAKE_SOURCE_DIR}/src/daemon/session.h
  Kiran::Session
  session_adaptor
  SessionAdaptor)

qt5_add_dbus_adaptor(
  USER_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.Authentication.User.xml
  ${CMAKE_SOURCE_DIR}/src/daemon/user.h Kiran::User user_adaptor UserAdaptor)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.AuthDevice.xml
  PROPERTIES CLASSNAME AuthDeviceManagerProxy NO_NAMESPACE true)

qt5_add_dbus_interface(
  BIOMETRICS_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.AuthDevice.xml
  auth_device_manager_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.AuthDevice.Device.xml
  PROPERTIES CLASSNAME AuthDeviceProxy NO_NAMESPACE true)

qt5_add_dbus_interface(
  BIOMETRICS_DEVICE_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/dbus/com.kylinsec.Kiran.AuthDevice.Device.xml
  auth_device_proxy)

set(TARGET_NAME kiran-authentication-daemon)

configure_file(config-daemon.h.in ${CMAKE_CURRENT_BINARY_DIR}/config-daemon.h)

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

add_executable(
  ${TARGET_NAME}
  ${H_FILES}
  ${CPP_FILES}
  ${AUTH_MANAGER_ADAPTOR_SRCS}
  ${AUTH_SESSION_ADAPTOR_SRCS}
  ${USER_ADAPTOR_SRCS}
  ${ACCOUNTS_INTERFACE_SRCS}
  ${ACCOUNTS_USER_INTERFACE_SRCS}
  ${BIOMETRICS_INTERFACE_SRCS}
  ${BIOMETRICS_DEVICE_INTERFACE_SRCS}
  ${QM_FILES})

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${PROJECT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include
          ${KLOG_QT5_INCLUDE_DIRS} ${KIRAN_CC_DAEMON_INCLUDE_DIRS})

target_link_libraries(
  ${TARGET_NAME} PRIVATE ${KLOG_QT5_LIBRARIES} ${KIRAN_CC_DAEMON_LIBRARIES}
                         Qt5::Core Qt5::DBus Qt5::Sql common)

install(FILES ${QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
