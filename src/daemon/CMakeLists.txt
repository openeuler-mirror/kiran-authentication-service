file(GLOB_RECURSE DAEMON_H_FILES ./*.h)
file(GLOB_RECURSE DAEMON_CPP_FILES ./*.cpp)

qt_add_dbus_adaptor(
  AUTH_MANAGER_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.xml
  ${CMAKE_SOURCE_DIR}/src/daemon/auth-manager.h
  Kiran::AuthManager
  auth_manager_adaptor
  AuthManagerAdaptor)

qt_add_dbus_adaptor(
  AUTH_SESSION_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.Session.xml
  ${CMAKE_SOURCE_DIR}/src/daemon/session.h
  Kiran::Session
  session_adaptor
  SessionAdaptor)

qt_add_dbus_adaptor(
  USER_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.User.xml
  ${CMAKE_SOURCE_DIR}/src/daemon/user.h Kiran::User user_adaptor UserAdaptor)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.xml
  PROPERTIES CLASSNAME AccountsProxy NO_NAMESPACE true)

qt_add_dbus_interface(
  ACCOUNTS_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.xml
  accounts_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.User.xml
  PROPERTIES CLASSNAME AccountsUserProxy NO_NAMESPACE true)

qt_add_dbus_interface(
  ACCOUNTS_USER_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.User.xml
  accounts_user_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.xml
  PROPERTIES CLASSNAME AuthDeviceManagerProxy NO_NAMESPACE true)

qt_add_dbus_interface(
  BIOMETRICS_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.xml auth_device_manager_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.Device.xml
  PROPERTIES CLASSNAME AuthDeviceProxy NO_NAMESPACE true)

qt_add_dbus_interface(
  BIOMETRICS_DEVICE_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.Device.xml
  auth_device_proxy)

set(TARGET_NAME kiran-authentication-daemon)

configure_file(config-daemon.h.in ${CMAKE_CURRENT_BINARY_DIR}/config-daemon.h)

set(DAEMON_TRANSLATOR_SOURCE 
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${PROJECT_SOURCE_DIR}
      ${PROJECT_SOURCE_DIR}/include
      ${PROJECT_SOURCE_DIR}/src/utils
      ${PROJECT_BINARY_DIR})
qt_create_translation(DAEMON_QM_FILES 
                      ${DAEMON_TRANSLATOR_SOURCE}
                      ${PROJECT_SOURCE_DIR}/translations/${TARGET_NAME}.zh_CN.ts
                      OPTIONS -I ${DAEMON_TRANSLATOR_SOURCE})

add_executable(
  ${TARGET_NAME}
  ${DAEMON_H_FILES}
  ${DAEMON_CPP_FILES}
  ${AUTH_MANAGER_ADAPTOR_SRCS}
  ${AUTH_SESSION_ADAPTOR_SRCS}
  ${USER_ADAPTOR_SRCS}
  ${ACCOUNTS_INTERFACE_SRCS}
  ${ACCOUNTS_USER_INTERFACE_SRCS}
  ${BIOMETRICS_INTERFACE_SRCS}
  ${BIOMETRICS_DEVICE_INTERFACE_SRCS}
  ${DAEMON_QM_FILES}
  ${UTILS_SRC})

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${PROJECT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include 
          ${KLOG_QT5_INCLUDE_DIRS}
          ${KIRAN_CC_DAEMON_INCLUDE_DIRS})

target_link_libraries(
  ${TARGET_NAME} PRIVATE ${KLOG_QT5_LIBRARIES} ${KIRAN_CC_DAEMON_LIBRARIES}
                         Qt5::Core Qt5::DBus)

install(FILES ${DAEMON_QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
