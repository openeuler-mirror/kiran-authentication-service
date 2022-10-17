# init variables
if(SYSTEMD_FOUND)
  pkg_get_variable(SYSTEM_UNIT_DIR systemd systemdsystemunitdir)
else()
  set(SYSTEM_UNIT_DIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
endif()

# .in files
configure_file(
  com.kylinsec.Kiran.Authentication.service.in
  ${PROJECT_BINARY_DIR}/data/com.kylinsec.Kiran.Authentication.service)

configure_file(kiran-authentication-daemon.service.in
               ${PROJECT_BINARY_DIR}/data/kiran-authentication-daemon.service)

# install
install(FILES com.kylinsec.Kiran.Authentication.conf
        DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/dbus-1/system.d)
install(
  FILES ${PROJECT_BINARY_DIR}/data/com.kylinsec.Kiran.Authentication.service
  DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/system-services)
install(FILES ${PROJECT_BINARY_DIR}/data/kiran-authentication-daemon.service
        DESTINATION ${SYSTEM_UNIT_DIR})

install(FILES kad.ini DESTINATION ${KAS_INSTALL_SYSCONFDIR})
