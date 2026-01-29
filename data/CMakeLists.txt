# init variables
if(SYSTEMD_FOUND)
  pkg_get_variable(SYSTEM_UNIT_DIR systemd systemdsystemunitdir)
else()
  set(SYSTEM_UNIT_DIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
endif()
# initd service directory
set(INITD_SERVICE_DIR "/etc/init.d/")

# systemd service files
file(GLOB SERVICE_IN_FILES services/systemd/*.service.in)
foreach(SERVICE_IN_FILE IN LISTS SERVICE_IN_FILES)
  string(REGEX REPLACE ".+/(.+)\\..*" "\\1" SERVICE_FILE ${SERVICE_IN_FILE})
  configure_file(${SERVICE_IN_FILE}
                 ${PROJECT_BINARY_DIR}/data/services/systemd/${SERVICE_FILE})
endforeach()

# install systemd service files
install(FILES dbus/com.kylinsec.Kiran.Authentication.conf
              dbus/com.kylinsec.Kiran.AuthDevice.conf
        DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/dbus-1/system.d)
install(
  FILES
    ${PROJECT_BINARY_DIR}/data/services/systemd/com.kylinsec.Kiran.Authentication.service
  DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/system-services)
install(
  FILES
    ${PROJECT_BINARY_DIR}/data/services/systemd/kiran-authentication-daemon.service
  DESTINATION ${SYSTEM_UNIT_DIR})
install(
  FILES
    ${PROJECT_BINARY_DIR}/data/services/systemd/com.kylinsec.Kiran.AuthDevice.service
  DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/system-services)
install(
  FILES
    ${PROJECT_BINARY_DIR}/data/services/systemd/kiran-authentication-devices.service
  DESTINATION ${SYSTEM_UNIT_DIR})

# install desktop autostart file for leave-detecter
# 使用桌面环境的 autostart 机制
configure_file(
  ${PROJECT_SOURCE_DIR}/data/autostart/kiran-leave-detecter.desktop.in
  ${PROJECT_BINARY_DIR}/data/autostart/kiran-leave-detecter.desktop
  @ONLY
)
install(
  FILES
    ${PROJECT_BINARY_DIR}/data/autostart/kiran-leave-detecter.desktop
  DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/xdg/autostart)

# install initd service files
install(
  FILES ${PROJECT_SOURCE_DIR}/data/services/initd/kiran-authentication-daemon
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
  DESTINATION ${INITD_SERVICE_DIR})
install(
  FILES ${PROJECT_SOURCE_DIR}/data/services/initd/kiran-authentication-devices
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
  DESTINATION ${INITD_SERVICE_DIR})

# install policy files
file(GLOB POLICY_IN_FILES ${PROJECT_SOURCE_DIR}/data/*.policy.in)
foreach(POLICY_IN_FILE IN LISTS POLICY_IN_FILES)
  string(REGEX REPLACE ".+/(.+)\\..*" "\\1" POLICY_FILE ${POLICY_IN_FILE})
  configure_file(${POLICY_IN_FILE} ${POLICY_FILE})
  install(FILES ${PROJECT_BINARY_DIR}/data/${POLICY_FILE}
          DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/polkit-1/actions/)
endforeach()

# install config files
install(FILES kad.ini DESTINATION ${KAS_INSTALL_SYSCONFDIR})
# install pam config files
install(FILES kiran-authentication-service
        DESTINATION /${CMAKE_INSTALL_SYSCONFDIR}/pam.d/)

install(
  FILES ${PROJECT_SOURCE_DIR}/data/zlog.conf
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ
              WORLD_WRITE
  DESTINATION ${KAS_INSTALL_DATADIR})