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

// ncnn YuNet 人脸检测器封装
// 参考: /mnt/1t/y/opencv/backport_452/ncnn_test.cpp

#include <ncnn/net.h>
#include <opencv2/core.hpp>
#include <opencv2/dnn.hpp>
#include <string>
#include <vector>

class YunetNcnn
{
public:
    // modelDir: 存放 yunet.param 与 yunet.bin 的目录
    explicit YunetNcnn(const std::string &modelDir);
    ~YunetNcnn() = default;

    // 输入图像尺寸变化时必须先调用
    void setInputSize(const cv::Size &s);

    // 检测人脸;返回 N x 15 CV_32F,布局同 OpenCV FaceDetectorYN:
    // [x, y, w, h, 5 点关键点(右眼/左眼/鼻尖/右嘴角/左嘴角), 置信度]
    // 未检测到人脸时返回空 Mat
    cv::Mat detect(const cv::Mat &image,
                   float scoreThreshold = 0.6f,
                   float nmsThreshold = 0.3f);

private:
    ncnn::Net m_net;
    int m_inputW = 0;
    int m_inputH = 0;
    int m_padW = 0;
    int m_padH = 0;
    static const int DIVISOR = 32;
    const std::vector<int> m_strides{8, 16, 32};
};
