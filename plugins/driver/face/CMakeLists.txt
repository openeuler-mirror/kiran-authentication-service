# 本地人脸识别驱动插件:基于 ncnn(YuNet 检测 + SFace 特征)
# 注意:独立于"软人脸"(ks-authhub 远端比对方案),类型为 DRIVER_TYPE_FACE
# 驱动为 Qt 驱动(参考 ks-authhub ks-soft-driver),自带翻译文件 face-driver.<locale>.qm
pkg_search_module(NCNN REQUIRED ncnn)
pkg_search_module(OPENCV REQUIRED opencv4)

set(TARGET_NAME face-driver)

set(TARGET_SOURCES
    face-driver.cpp
    face-driver.h
    yunet-ncnn.cpp
    yunet-ncnn.h
    sface-ncnn.cpp
    sface-ncnn.h)

# 翻译文件:lupdate 收集 QT_TRANSLATE_NOOP 词条,lrelease 生成 qm
set(QM_FILES "")
foreach(LANG ${LANGUAGES})
  set(TS_FILE "${PROJECT_SOURCE_DIR}/translations/${TARGET_NAME}.${LANG}.ts")
  execute_process(COMMAND lupdate-qt5 -no-obsolete ${TARGET_SOURCES} -ts
                          ${TS_FILE}
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  set(QM_FILE "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.${LANG}.qm")
  execute_process(COMMAND lrelease-qt5 ${TS_FILE} -qm ${QM_FILE}
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  list(APPEND QM_FILES ${QM_FILE})
  message(STATUS "QM_FILE: ${QM_FILE}")
endforeach()

add_library(${TARGET_NAME} MODULE ${TARGET_SOURCES} ${QM_FILES})

target_include_directories(${TARGET_NAME} PRIVATE
                           ${NCNN_INCLUDE_DIRS}
                           ${OPENCV_INCLUDE_DIRS}
                           ${PROJECT_SOURCE_DIR}/include
                           ${PROJECT_BINARY_DIR})

target_link_libraries(${TARGET_NAME} PRIVATE
                      Qt5::Core
                      ${NCNN_LIBRARIES}
                      ${OPENCV_LIBRARIES})

install(TARGETS ${TARGET_NAME}
        LIBRARY DESTINATION ${KAS_AUTH_DRIVERSDIR})
install(FILES ${QM_FILES} DESTINATION ${KAS_INSTALL_TRANSLATIONDIR})

# 算法基准验证工具(构建期验证,不安装)
add_executable(face-algo-benchmark
               face-algo-benchmark.cpp
               yunet-ncnn.cpp
               sface-ncnn.cpp)

target_include_directories(face-algo-benchmark PRIVATE
                           ${NCNN_INCLUDE_DIRS}
                           ${OPENCV_INCLUDE_DIRS}
                           ${PROJECT_SOURCE_DIR}/include
                           ${PROJECT_BINARY_DIR})

target_link_libraries(face-algo-benchmark PRIVATE
                      ${NCNN_LIBRARIES}
                      ${OPENCV_LIBRARIES})
