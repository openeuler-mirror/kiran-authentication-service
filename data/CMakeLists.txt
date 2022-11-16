# init variables
if(SYSTEMD_FOUND)
  pkg_get_variable(SYSTEM_UNIT_DIR systemd systemdsystemunitdir)
else()
  set(SYSTEM_UNIT_DIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
endif()

# policy files
file(GLOB POLICY_IN_FILES ${PROJECT_SOURCE_DIR}/data/*.policy.in)

foreach(POLICY_IN_FILE IN LISTS POLICY_IN_FILES)
  string(REGEX REPLACE ".+/(.+)\\..*" "\\1" POLICY_FILE ${POLICY_IN_FILE})
  configure_file(${POLICY_IN_FILE} ${POLICY_FILE})
  install(FILES ${PROJECT_BINARY_DIR}/data/${POLICY_FILE}
          DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/polkit-1/actions/)
endforeach()

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
