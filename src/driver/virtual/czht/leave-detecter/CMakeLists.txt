set(TARGET_NAME kiran-leave-detecter)

find_package(Qt5 REQUIRED COMPONENTS DBus Core Widgets)

add_executable(${TARGET_NAME} leave-detecter.cpp leave-detecter.h main.cpp)

target_include_directories(
  ${TARGET_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_BINARY_DIR}
          ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include
          ${KLOG_QT5_INCLUDE_DIRS} ${CZHT_INCLUDE_DIRS})

target_link_libraries(${TARGET_NAME} PRIVATE Qt5::Widgets Qt5::DBus Qt5::Core
                                                  ${KLOG_QT5_LIBRARIES})

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
