/**
 * Copyright (c) 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#pragma once

// 人脸驱动错误码(本地识别,驱动插件内部使用,不对外安装)
// 设备层只区分"成功(0)与其他",具体错误码文案由驱动 getErrorMsg 按 locale 提供。

enum FaceDriverError
{
    FACE_DRIVER_ERROR_SUCCESS = 0,
    // 摄像头类 1xx
    FACE_DRIVER_ERROR_OPEN_CAMERA = 101,    // 打开摄像头失败
    FACE_DRIVER_ERROR_CAPTURE = 102,        // 采集失败
    FACE_DRIVER_ERROR_CAMERA_CLOSED = 103,  // 摄像头已关闭
    // 算法类 2xx
    FACE_DRIVER_ERROR_LOAD_MODEL = 201,     // 模型加载失败
    FACE_DRIVER_ERROR_NO_FACE = 202,        // 未检测到人脸或质量不达标
    FACE_DRIVER_ERROR_MULTI_FACE = 203,     // 画面中存在多张人脸(保留备用,当前实现多脸取最大脸不再返回此码)
    FACE_DRIVER_ERROR_EXTRACT = 204,        // 特征提取失败
    // 录入类 3xx
    FACE_DRIVER_ERROR_DECODE_IMAGE = 301,   // 图像解码失败
    FACE_DRIVER_ERROR_DUPLICATE = 302,      // 特征重复录入
    FACE_DRIVER_ERROR_SAVE = 303,           // 特征保存失败
    // 识别类 4xx
    FACE_DRIVER_ERROR_NOT_MATCH = 401,      // 比对不匹配(识别正常结束)
    FACE_DRIVER_ERROR_TIMEOUT = 402,        // 识别超时
    FACE_DRIVER_ERROR_STOPPED = 403,        // 识别被停止
};
