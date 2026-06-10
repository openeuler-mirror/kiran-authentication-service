set(VIRTUAL_DRIVERS_INSTALL_DIR ${KAS_AUTH_DRIVERSDIR}/virtual)

if(ENABLE_CZHT_VIRTUAL_DRIVER)
    add_subdirectory(czht)
endif()

if(ENABLE_KIRAN_FACE_DRIVER)
    add_subdirectory(kiran)
endif()
