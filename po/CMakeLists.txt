find_program (MSGFMT NAMES "msgfmt")

add_custom_target (ZH_MO ALL ${MSGFMT} zh_CN.po -D ../../po -o ${PROJECT_BINARY_DIR}/zh_CN.mo)
install(FILES ${PROJECT_BINARY_DIR}/zh_CN.mo DESTINATION ${CMAKE_INSTALL_PREFIX}/share/locale/zh_CN/LC_MESSAGES/ RENAME ${PROJECT_NAME}.mo)
