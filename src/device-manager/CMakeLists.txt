pkg_search_module(LIBUDEV REQUIRED libudev)

set(TARGET_NAME kiran-authentication-devices)

file(GLOB_RECURSE H_FILES ./*.h)
file(GLOB_RECURSE CPP_FILES ./*.cpp)

# 定义支持的语言列表
set(LANGUAGES zh_CN) # 可以添加更多语言  # set(LANGUAGES zh_CN bo_CN ug_CN mn_MN ky_KG kk_KZ)

# 定义翻译源文件列表
set(QM_FILES "")

foreach(LANG ${LANGUAGES})
  # ts 文件路径
  set(TS_FILE "${PROJECT_SOURCE_DIR}/translations/${TARGET_NAME}.${LANG}.ts")

  # 执行 lupdate 更新 ts 文件
  execute_process(COMMAND lupdate-qt5 -no-obsolete ${H_FILES} ${CPP_FILES} -ts
                          ${TS_FILE})

  # 生成 qm 文件
  qt5_add_translation(QM_FILE ${TS_FILE})
  list(APPEND QM_FILES ${QM_FILE})
endforeach()

qt5_add_dbus_adaptor(
  AUTH_DEVICE_MANAGER_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.xml
  ${CMAKE_SOURCE_DIR}/src/device-manager/manager.h
  Kiran::Manager
  auth_device_manager_adaptor
  AuthDeviceManagerAdaptor)

qt5_add_dbus_adaptor(
  AUTH_DEVICE_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.Device.xml
  ${CMAKE_SOURCE_DIR}/src/device-manager/device/device.h
  Kiran::Device
  auth_device_adaptor
  AuthDeviceAdaptor)

add_executable(
  ${TARGET_NAME} ${H_FILES} ${CPP_FILES} ${AUTH_DEVICE_MANAGER_ADAPTOR_SRCS}
                 ${AUTH_DEVICE_ADAPTOR_SRCS} ${QM_FILES})

target_include_directories(
  ${TARGET_NAME} PUBLIC ${KLOG_QT5_INCLUDE_DIRS} ${PROJECT_BINARY_DIR}
                        ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(
  ${TARGET_NAME}
  ${KLOG_QT5_LIBRARIES}
  ${LIBUDEV_LIBRARIES}
  Qt5::Core
  Qt5::DBus
  Qt5::Concurrent
  Qt5::Sql
  ${CMAKE_DL_LIBS}
  common)

# 安装 driver 文件夹，用于提供给其他开发者使用
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/driver
        DESTINATION ${KAS_INSTALL_INCLUDE})

install(FILES ${QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})
install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
