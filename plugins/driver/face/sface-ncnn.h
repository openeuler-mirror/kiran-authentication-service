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

// ncnn SFace 人脸识别器封装(128 维特征 + 余弦相似度)
// 参考: /mnt/1t/y/opencv/backport_452/ncnn_test.cpp

#include <ncnn/net.h>
#include <opencv2/core.hpp>
#include <string>
#include <vector>

class SfaceNcnn
{
public:
    // modelDir: 存放 sface.param 与 sface.bin 的目录
    explicit SfaceNcnn(const std::string &modelDir);
    ~SfaceNcnn() = default;

    // 用检测结果的 5 点关键点对齐并裁剪到 112x112
    // faceRow: 检测结果的一行(1 x 15 CV_32F)
    cv::Mat alignCrop(const cv::Mat &srcImg, const cv::Mat &faceRow);

    // 提取 128 维特征(1 x 128 CV_32F)
    cv::Mat feature(const cv::Mat &aligned112);

    // 余弦相似度(越大越像;参考基准:同人约 0.885,异人约 0.179)
    static double match(const cv::Mat &f1, const cv::Mat &f2);

    // 特征矩阵转字节序列(用于存储/比对)
    static std::vector<uint8_t> featureToBytes(const cv::Mat &feat);

    // 字节序列转特征矩阵(用于存储/比对)
    static cv::Mat bytesToFeature(const std::vector<uint8_t> &bytes);

private:
    cv::Mat getSimilarityTransformMatrix(float src[5][2]) const;

    ncnn::Net m_net;
};
