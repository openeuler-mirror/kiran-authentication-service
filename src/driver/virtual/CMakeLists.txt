set(VIRTUAL_DRIVERS_INSTALL_DIR ${KAS_AUTH_DRIVERSDIR}/virtual)

if(ENABLE_CZHT_VIRTUAL_DRIVER)
    add_subdirectory(czht)
endif()
