set(CZHT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(VIRTUAL_CZHT_DRIVER_INSTALL_DIR ${VIRTUAL_DRIVERS_INSTALL_DIR}/czht)

add_subdirectory(face)
add_subdirectory(code)
add_subdirectory(gen-code)
add_subdirectory(screen-recorder)
add_subdirectory(leave-detecter)
add_subdirectory(data)
