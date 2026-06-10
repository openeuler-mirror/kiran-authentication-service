set(KIRAN_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(VIRTUAL_KIRAN_DRIVER_INSTALL_DIR ${VIRTUAL_DRIVERS_INSTALL_DIR}/kiran)

add_subdirectory(face)
add_subdirectory(code)
add_subdirectory(data)
add_subdirectory(gen-code)
add_subdirectory(leave-detecter)
# screen-recorder 直接复用 czht 版本（无 D-Bus 依赖）
