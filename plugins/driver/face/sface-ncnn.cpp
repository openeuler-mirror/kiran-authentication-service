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

#include "sface-ncnn.h"

#include <cfloat>
#include <cstring>
#include <stdexcept>
#include <opencv2/imgproc.hpp>

SfaceNcnn::SfaceNcnn(const std::string &modelDir)
{
    const std::string paramPath = modelDir + "/sface.param";
    const std::string binPath = modelDir + "/sface.bin";

    m_net.opt.num_threads = 4;
    if (0 != m_net.load_param(paramPath.c_str()))
    {
        throw std::runtime_error("load sface.param failed: " + paramPath);
    }
    if (0 != m_net.load_model(binPath.c_str()))
    {
        throw std::runtime_error("load sface.bin failed: " + binPath);
    }
    m_net.opt.use_vulkan_compute = false;
}

cv::Mat SfaceNcnn::alignCrop(const cv::Mat &srcImg, const cv::Mat &faceRow)
{
    float src[5][2];
    for (int row = 0; row < 5; ++row)
    {
        for (int col = 0; col < 2; ++col)
        {
            src[row][col] = faceRow.at<float>(0, row * 2 + col + 4);
        }
    }
    cv::Mat warp = getSimilarityTransformMatrix(src);
    cv::Mat aligned;
    cv::warpAffine(srcImg, aligned, warp, cv::Size(112, 112), cv::INTER_LINEAR);
    return aligned;
}

cv::Mat SfaceNcnn::feature(const cv::Mat &aligned112)
{
    // 模型头部自带 (x-127.5)/128 预处理,喂原始 RGB 0-255
    ncnn::Mat in = ncnn::Mat::from_pixels(aligned112.data, ncnn::Mat::PIXEL_RGB, 112, 112);
    const float norm[3] = {1.f, 1.f, 1.f};
    in.substract_mean_normalize(0, norm);
    ncnn::Extractor ex = m_net.create_extractor();
    ex.input("data", in);
    ncnn::Mat out;
    ex.extract("fc1", out);
    cv::Mat feat(1, out.w, CV_32F);
    memcpy(feat.data, out.data, out.w * sizeof(float));
    return feat;
}

double SfaceNcnn::match(const cv::Mat &f1, const cv::Mat &f2)
{
    cv::Mat a = f1.clone();
    cv::Mat b = f2.clone();
    cv::normalize(a, a);
    cv::normalize(b, b);
    return cv::sum(a.mul(b))[0];
}

std::vector<uint8_t> SfaceNcnn::featureToBytes(const cv::Mat &feat)
{
    std::vector<uint8_t> bytes(feat.total() * feat.elemSize());
    memcpy(bytes.data(), feat.data, bytes.size());
    return bytes;
}

cv::Mat SfaceNcnn::bytesToFeature(const std::vector<uint8_t> &bytes)
{
    cv::Mat feat(1, static_cast<int>(bytes.size() / sizeof(float)), CV_32F);
    memcpy(feat.data, bytes.data(), bytes.size());
    return feat;
}

cv::Mat SfaceNcnn::getSimilarityTransformMatrix(float src[5][2]) const
{
    float dst[5][2] = {{38.2946f, 51.6963f},
                       {73.5318f, 51.5014f},
                       {56.0252f, 71.7366f},
                       {41.5493f, 92.3655f},
                       {70.7299f, 92.2041f}};
    float avg0 = (src[0][0] + src[1][0] + src[2][0] + src[3][0] + src[4][0]) / 5;
    float avg1 = (src[0][1] + src[1][1] + src[2][1] + src[3][1] + src[4][1]) / 5;
    float srcMean[2] = {avg0, avg1};
    float dstMean[2] = {56.0262f, 71.9008f};

    float srcDemean[5][2], dstDemean[5][2];
    for (int i = 0; i < 2; i++)
    {
        for (int j = 0; j < 5; j++)
        {
            srcDemean[j][i] = src[j][i] - srcMean[i];
            dstDemean[j][i] = dst[j][i] - dstMean[i];
        }
    }

    double A00 = 0.0, A01 = 0.0, A10 = 0.0, A11 = 0.0;
    for (int i = 0; i < 5; i++)
    {
        A00 += dstDemean[i][0] * srcDemean[i][0];
        A01 += dstDemean[i][0] * srcDemean[i][1];
        A10 += dstDemean[i][1] * srcDemean[i][0];
        A11 += dstDemean[i][1] * srcDemean[i][1];
    }
    A00 /= 5; A01 /= 5; A10 /= 5; A11 /= 5;
    cv::Mat A = (cv::Mat_<double>(2, 2) << A00, A01, A10, A11);
    double d[2] = {1.0, 1.0};
    double detA = A00 * A11 - A01 * A10;
    if (detA < 0)
    {
        d[1] = -1;
    }
    double T[3][3] = {{1.0, 0.0, 0.0}, {0.0, 1.0, 0.0}, {0.0, 0.0, 1.0}};

    cv::Mat s, u, vt;
    cv::SVD::compute(A, s, u, vt);
    double smax = std::max(s.ptr<double>(0)[0], s.ptr<double>(1)[0]);
    double tol = smax * 2 * FLT_MIN;
    int rank = 0;
    if (s.ptr<double>(0)[0] > tol)
    {
        rank += 1;
    }
    if (s.ptr<double>(1)[0] > tol)
    {
        rank += 1;
    }

    double arrU[2][2] = {{u.ptr<double>(0)[0], u.ptr<double>(0)[1]},
                         {u.ptr<double>(1)[0], u.ptr<double>(1)[1]}};
    double arrVt[2][2] = {{vt.ptr<double>(0)[0], vt.ptr<double>(0)[1]},
                          {vt.ptr<double>(1)[0], vt.ptr<double>(1)[1]}};
    double detU = arrU[0][0] * arrU[1][1] - arrU[0][1] * arrU[1][0];
    double detVt = arrVt[0][0] * arrVt[1][1] - arrVt[0][1] * arrVt[1][0];

    if (rank == 1)
    {
        if ((detU * detVt) > 0)
        {
            cv::Mat uvt = u * vt;
            T[0][0] = uvt.ptr<double>(0)[0];
            T[0][1] = uvt.ptr<double>(0)[1];
            T[1][0] = uvt.ptr<double>(1)[0];
            T[1][1] = uvt.ptr<double>(1)[1];
        }
        else
        {
            double temp = d[1];
            d[1] = -1;
            cv::Mat D = (cv::Mat_<double>(2, 2) << d[0], 0.0, 0.0, d[1]);
            cv::Mat uDvt = u * (D * vt);
            T[0][0] = uDvt.ptr<double>(0)[0];
            T[0][1] = uDvt.ptr<double>(0)[1];
            T[1][0] = uDvt.ptr<double>(1)[0];
            T[1][1] = uDvt.ptr<double>(1)[1];
            d[1] = temp;
        }
    }
    else
    {
        cv::Mat D = (cv::Mat_<double>(2, 2) << d[0], 0.0, 0.0, d[1]);
        cv::Mat uDvt = u * (D * vt);
        T[0][0] = uDvt.ptr<double>(0)[0];
        T[0][1] = uDvt.ptr<double>(0)[1];
        T[1][0] = uDvt.ptr<double>(1)[0];
        T[1][1] = uDvt.ptr<double>(1)[1];
    }

    double var1 = 0.0, var2 = 0.0;
    for (int i = 0; i < 5; i++)
    {
        var1 += srcDemean[i][0] * srcDemean[i][0];
        var2 += srcDemean[i][1] * srcDemean[i][1];
    }
    var1 /= 5;
    var2 /= 5;
    double scale = 1.0 / (var1 + var2) * (s.ptr<double>(0)[0] * d[0] + s.ptr<double>(1)[0] * d[1]);
    double TS[2];
    TS[0] = T[0][0] * srcMean[0] + T[0][1] * srcMean[1];
    TS[1] = T[1][0] * srcMean[0] + T[1][1] * srcMean[1];
    T[0][2] = dstMean[0] - scale * TS[0];
    T[1][2] = dstMean[1] - scale * TS[1];
    T[0][0] *= scale;
    T[0][1] *= scale;
    T[1][0] *= scale;
    T[1][1] *= scale;

    return (cv::Mat_<double>(2, 3) << T[0][0], T[0][1], T[0][2],
            T[1][0], T[1][1], T[1][2]);
}
