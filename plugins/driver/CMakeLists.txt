# 本地人脸识别驱动依赖 ncnn + opencv4；缺依赖时跳过插件，不影响 pam/daemon 等核心组件构建。
option(BUILD_FACE_DRIVER "Build local face recognition driver plugin" ON)

if(BUILD_FACE_DRIVER)
    pkg_search_module(NCNN ncnn)
    pkg_search_module(OPENCV opencv4)
    if(NCNN_FOUND AND OPENCV_FOUND)
        add_subdirectory(face)
    else()
        message(WARNING
            "BUILD_FACE_DRIVER=ON but ncnn/opencv4 not found; skipping face-driver plugin. "
            "Install ncnn and opencv4 devel packages, or pass -DBUILD_FACE_DRIVER=OFF.")
    endif()
endif()
