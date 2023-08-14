find_package (PkgConfig REQUIRED)
find_package (OpenSSL REQUIRED)

pkg_check_modules (GLIB2 REQUIRED glib-2.0)
pkg_check_modules (GIO REQUIRED gio-2.0)
pkg_check_modules (GIO_UNIX REQUIRED gio-unix-2.0)
pkg_check_modules (GLIB_JSON REQUIRED json-glib-1.0)
pkg_check_modules (KIRAN_CC_DAEMON REQUIRED kiran-cc-daemon)

if (ENABLE_ZLOG_EX)
      pkg_search_module(ZLOG REQUIRED zlog)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_ZLOG_EX")
else()
      find_library(ZLOG_LIBRARY zlog)
      set (ZLOG_INCLUDE_DIRS "")
      set (ZLOG_LIBRARIES "${ZLOG_LIBRARY}")
endif()

message("found zlog dirs: ${ZLOG_INCLUDE_DIRS}")
message("found zlog libs: ${ZLOG_LIBRARIES}")

find_library(PAM_LIBRARY pam)
find_program(GDBUS_CODEGEN "gdbus-codegen")

if (NOT GDBUS_CODEGEN)
    message(FATAL_ERROR "gdbus-codegen program not found")
else()
    message("found ${GDBUS_CODEGEN}")
endif (NOT GDBUS_CODEGEN)

add_custom_command(OUTPUT kiran-authentication-gen.c kiran-authentication-gen.h
    COMMAND ${GDBUS_CODEGEN} --c-namespace Kiran --interface-prefix com.kylinsec.Kiran.SystemDaemon --generate-c-code kiran-authentication-gen  ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Authentication.xml
    DEPENDS ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Authentication.xml
)

add_custom_command(OUTPUT kiran-user-gen.c kiran-user-gen.h
    COMMAND ${GDBUS_CODEGEN} --c-namespace Kiran --interface-prefix com.kylinsec.Kiran.SystemDaemon --generate-c-code kiran-user-gen  ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.User.xml
    DEPENDS ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.User.xml
)

add_custom_command(OUTPUT kiran-accounts-gen.c kiran-accounts-gen.h
    COMMAND ${GDBUS_CODEGEN} --c-namespace Kiran --interface-prefix com.kylinsec.Kiran.SystemDaemon --generate-c-code kiran-accounts-gen  ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.xml
    DEPENDS  ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Accounts.xml
)

add_custom_command(OUTPUT kiran-biometrics-gen.c kiran-biometrics-gen.h
    COMMAND ${GDBUS_CODEGEN} --c-namespace Kiran --interface-prefix com.kylinsec.Kiran.SystemDaemon --generate-c-code kiran-biometrics-gen  ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Biometrics.xml
    DEPENDS  ${PROJECT_SOURCE_DIR}/data/com.kylinsec.Kiran.SystemDaemon.Biometrics.xml
)

configure_file(${SRC_DIR}/config.h.in config.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${GLIB_JSON_INCLUDE_DIRS} ${KIRAN_CC_DAEMON_INCLUDE_DIRS})

include_directories(${ZLOG_INCLUDE_DIRS} ${GLIB2_INCLUDE_DIRS} ${GIO_INCLUDE_DIRS} ${GIO_UNIX_INCLUDE_DIRS})
add_executable (kiran_authentication_service main.c kiran-authentication-gen.c kiran-auth-service.c kiran-accounts-gen.c kiran-user-gen.c kiran-biometrics-gen.c kiran-authentication.c)
target_link_libraries(kiran_authentication_service pam ${ZLOG_LIBRARIES} ${GLIB2_LIBRARIES} ${GIO_LIBRARIES} ${GIO_UNIX_LIBRARIES} ${GLIB_JSON_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARIES} pthread)
install(TARGETS kiran_authentication_service RUNTIME DESTINATION ${INSTALL_BINDIR})

add_library(pam_kiran_authentication MODULE pam-kiran-authentication.c kiran-authentication-gen.c)
set_target_properties(pam_kiran_authentication PROPERTIES PREFIX "")
target_link_libraries(pam_kiran_authentication pam_misc ${GLIB2_LIBRARIES} ${GDBUS_LIBRARIES} ${GLIB_JSON_LIBRARIES})
install(TARGETS pam_kiran_authentication LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/security/)

add_library(kiran-authentication-service SHARED kiran-authentication.c)
target_link_libraries(kiran-authentication-service ${OPENSSL_CRYPTO_LIBRARIES})
set_target_properties(kiran-authentication-service PROPERTIES VERSION 0.0.1 SOVERSION 0.1)
install(TARGETS kiran-authentication-service LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/)

install(FILES authentication_i.h  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
