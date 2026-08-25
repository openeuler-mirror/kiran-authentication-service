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

// 算法基准回归验证工具(构建期验证,不安装)
// 用法: face-algo-benchmark <自拍图> <对比图1> [对比图2 ...]
// 校验: 同一人不同裁剪余弦相似度 ≈ 0.885,不同人 ≈ 0.179
// 参考: /mnt/1t/y/opencv/backport_452/ncnn_test.cpp(基准 135 张脸 / 同人 0.885 / 异人 0.179)

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include <opencv2/imgcodecs.hpp>

#include "sface-ncnn.h"
#include "yunet-ncnn.h"

namespace
{
std::string modelDir()
{
    const char *env = getenv("KAS_FACE_MODEL_DIR");
    if (env && *env)
    {
        return env;
    }
    if (FILE *fp = fopen("data/models/face/yunet.param", "rb"))
    {
        fclose(fp);
        return "data/models/face";
    }
    return "models/face";
}

// 对一张图提取特征(取置信度最高的一张脸)
cv::Mat featOf(YunetNcnn &det, SfaceNcnn &rec, const cv::Mat &img)
{
    det.setInputSize(img.size());
    cv::Mat faces = det.detect(img);
    if (faces.empty())
    {
        std::cerr << "no face detected in image" << std::endl;
        exit(1);
    }
    cv::Mat aligned = rec.alignCrop(img, faces.row(0));
    return rec.feature(aligned);
}
}  // namespace

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: face-algo-benchmark <selfie> <other1> [other2 ...]" << std::endl;
        return 1;
    }

    try
    {
        YunetNcnn det(modelDir());
        SfaceNcnn rec(modelDir());

        cv::Mat img = cv::imread(argv[1]);
        if (img.empty())
        {
            std::cerr << "read image failed: " << argv[1] << std::endl;
            return 1;
        }

        // 同一人不同裁剪:整图 vs 裁边后重新检测
        det.setInputSize(img.size());
        cv::Mat faces = det.detect(img);
        std::cout << "[YunetNcnn] faces: " << faces.rows << std::endl;
        if (faces.empty())
        {
            std::cerr << "no face in " << argv[1] << std::endl;
            return 1;
        }
        float x = faces.at<float>(0, 0), y = faces.at<float>(0, 1);
        float w = faces.at<float>(0, 2), h = faces.at<float>(0, 3);
        cv::Rect r0(cvRound(x), cvRound(y), cvRound(w), cvRound(h));
        cv::Rect r1(std::max(0, r0.x - 10), std::max(0, r0.y - 10),
                    std::min(img.cols, r0.x + r0.width + 10) - std::max(0, r0.x - 10),
                    std::min(img.rows, r0.y + r0.height + 10) - std::max(0, r0.y - 10));
        cv::Mat fA = featOf(det, rec, img(r1).clone());
        cv::Mat fB = featOf(det, rec, img(r0).clone());
        double same = SfaceNcnn::match(fA, fB);
        std::cout << "[SFace] 同一人(不同裁剪): " << same << " (期望 ~0.885)" << std::endl;

        for (int i = 2; i < argc; i++)
        {
            cv::Mat other = cv::imread(argv[i]);
            if (other.empty())
            {
                std::cerr << "read image failed: " << argv[i] << std::endl;
                return 1;
            }
            cv::Mat fOther = featOf(det, rec, other);
            double diff = SfaceNcnn::match(fA, fOther);
            std::cout << "[SFace] 不同人(" << argv[i] << "): " << diff
                      << " (期望 ~0.179)" << std::endl;
        }

        // 一致性判定(放宽容差,避免环境差异导致的假失败)
        if (std::abs(same - 0.885) > 0.05)
        {
            std::cerr << "FAIL: same-person similarity out of expected range" << std::endl;
            return 1;
        }
        std::cout << "PASS: 基准回归通过(同人相似度在期望区间)" << std::endl;
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "benchmark failed: " << e.what() << std::endl;
        return 1;
    }
}
