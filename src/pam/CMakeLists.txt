file(GLOB_RECURSE PAM_H_FILES ./*.h)
file(GLOB_RECURSE PAM_CPP_FILES ./*.cpp)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.xml
  PROPERTIES CLASSNAME AuthManagerProxy NO_NAMESPACE true)

qt_add_dbus_interface(
  AUTH_MANAGER_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.xml
  auth_manager_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.Session.xml
  PROPERTIES CLASSNAME AuthSessionProxy NO_NAMESPACE true)

qt_add_dbus_interface(
  AUTH_SESSION_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.Session.xml
  auth_session_proxy)

set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.User.xml
  PROPERTIES CLASSNAME AuthUserProxy NO_NAMESPACE true)

qt_add_dbus_interface(
  AUTH_USER_INTERFACE_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.Authentication.User.xml
  auth_user_proxy)

set(TARGET_NAME pam_kiran_authentication)

configure_file(config-pam.h.in ${CMAKE_CURRENT_BINARY_DIR}/config-pam.h)

set(PAM_TRANSLATOR_SOURCE 
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/../utils/
      ${PROJECT_SOURCE_DIR})
qt_create_translation(PAM_QM_FILES 
                      ${PAM_TRANSLATOR_SOURCE}
                      ${PROJECT_SOURCE_DIR}/translations/${TARGET_NAME}.zh_CN.ts
                      OPTIONS -I ${PAM_TRANSLATOR_SOURCE})

add_library(
  ${TARGET_NAME} SHARED
  ${PAM_H_FILES} ${PAM_CPP_FILES} ${AUTH_MANAGER_INTERFACE_SRCS} ${UTILS_SRC}
  ${AUTH_SESSION_INTERFACE_SRCS} ${AUTH_USER_INTERFACE_SRCS} ${PAM_QM_FILES})

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR}
          ${PROJECT_SOURCE_DIR}/include ${KLOG_QT5_INCLUDE_DIRS}
          ${PAM_INCLUDE_DIRS})

target_link_libraries(
  ${TARGET_NAME} PRIVATE ${KLOG_QT5_LIBRARIES} ${PAM_LIBRARIES} Qt5::Core
                         Qt5::DBus)

set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")

install(FILES ${PAM_QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
install(TARGETS ${TARGET_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/security/)
