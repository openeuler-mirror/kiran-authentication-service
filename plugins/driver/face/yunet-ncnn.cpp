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

#include "yunet-ncnn.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <opencv2/imgproc.hpp>

YunetNcnn::YunetNcnn(const std::string &modelDir)
{
    const std::string paramPath = modelDir + "/yunet.param";
    const std::string binPath = modelDir + "/yunet.bin";

    m_net.opt.num_threads = 4;
    if (0 != m_net.load_param(paramPath.c_str()))
    {
        throw std::runtime_error("load yunet.param failed: " + paramPath);
    }
    if (0 != m_net.load_model(binPath.c_str()))
    {
        throw std::runtime_error("load yunet.bin failed: " + binPath);
    }
    m_net.opt.use_vulkan_compute = false;
}

void YunetNcnn::setInputSize(const cv::Size &s)
{
    m_inputW = s.width;
    m_inputH = s.height;
    m_padW = ((m_inputW - 1) / DIVISOR + 1) * DIVISOR;
    m_padH = ((m_inputH - 1) / DIVISOR + 1) * DIVISOR;
}

cv::Mat YunetNcnn::detect(const cv::Mat &image,
                          float scoreThreshold,
                          float nmsThreshold)
{
    cv::Mat padImage;
    cv::copyMakeBorder(image, padImage, 0, m_padH - m_inputH, 0, m_padW - m_inputW,
                       cv::BORDER_CONSTANT, 0);

    ncnn::Mat in = ncnn::Mat::from_pixels(padImage.data, ncnn::Mat::PIXEL_BGR,
                                          m_padW, m_padH);
    const float norm[3] = {1.f, 1.f, 1.f};
    in.substract_mean_normalize(0, norm);  // u8 -> fp32, 值域 0-255

    ncnn::Extractor ex = m_net.create_extractor();
    ex.input("input", in);

    ncnn::Mat cls[3], obj[3], bbox[3], kps[3];
    const char *names[3] = {"8", "16", "32"};
    for (int i = 0; i < 3; i++)
    {
        ex.extract((std::string("cls_") + names[i]).c_str(), cls[i]);
        ex.extract((std::string("obj_") + names[i]).c_str(), obj[i]);
        ex.extract((std::string("bbox_") + names[i]).c_str(), bbox[i]);
        ex.extract((std::string("kps_") + names[i]).c_str(), kps[i]);
    }

    cv::Mat faces;
    for (size_t i = 0; i < m_strides.size(); ++i)
    {
        int cols = m_padW / m_strides[i];
        int rows = m_padH / m_strides[i];
        const float *clsV = cls[i];
        const float *objV = obj[i];
        const float *bboxV = bbox[i];
        const float *kpsV = kps[i];

        cv::Mat face(1, 15, CV_32FC1);
        for (int r = 0; r < rows; ++r)
        {
            for (int c = 0; c < cols; ++c)
            {
                size_t idx = (size_t)r * cols + c;
                float clsScore = std::min(std::max(clsV[idx], 0.f), 1.f);
                float objScore = std::min(std::max(objV[idx], 0.f), 1.f);
                float score = std::sqrt(clsScore * objScore);
                face.at<float>(0, 14) = score;
                if (score < scoreThreshold)
                {
                    continue;
                }

                float cx = ((c + bboxV[idx * 4 + 0]) * m_strides[i]);
                float cy = ((r + bboxV[idx * 4 + 1]) * m_strides[i]);
                float w = std::exp(bboxV[idx * 4 + 2]) * m_strides[i];
                float h = std::exp(bboxV[idx * 4 + 3]) * m_strides[i];

                face.at<float>(0, 0) = cx - w / 2.f;
                face.at<float>(0, 1) = cy - h / 2.f;
                face.at<float>(0, 2) = w;
                face.at<float>(0, 3) = h;
                for (int n = 0; n < 5; ++n)
                {
                    face.at<float>(0, 4 + 2 * n) = (kpsV[idx * 10 + 2 * n] + c) * m_strides[i];
                    face.at<float>(0, 4 + 2 * n + 1) = (kpsV[idx * 10 + 2 * n + 1] + r) * m_strides[i];
                }
                faces.push_back(face);
            }
        }
    }

    if (faces.rows > 1)
    {
        std::vector<cv::Rect> faceBoxes;
        std::vector<float> faceScores;
        for (int rIdx = 0; rIdx < faces.rows; rIdx++)
        {
            faceBoxes.push_back(cv::Rect(int(faces.at<float>(rIdx, 0)),
                                         int(faces.at<float>(rIdx, 1)),
                                         int(faces.at<float>(rIdx, 2)),
                                         int(faces.at<float>(rIdx, 3))));
            faceScores.push_back(faces.at<float>(rIdx, 14));
        }
        std::vector<int> keepIdx;
        cv::dnn::NMSBoxes(faceBoxes, faceScores, scoreThreshold, nmsThreshold,
                          keepIdx, 1.f, 5000);
        cv::Mat nmsFaces;
        for (size_t i = 0; i < keepIdx.size(); ++i)
        {
            nmsFaces.push_back(faces.row(keepIdx[i]));
        }
        return nmsFaces;
    }
    return faces;
}
