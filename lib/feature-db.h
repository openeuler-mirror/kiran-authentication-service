/**
 * Copyright (c) 2025 ~ 2026 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     yangfeng <yangfeng@kylinsec.com.cn>
 */

#pragma once

#include "feature-data.h"

namespace Kiran
{
class FeatureDB
{
public:
    explicit FeatureDB();
    ~FeatureDB();

    static FeatureDB *getInstance() { return m_instance; };
    static void globalInit();
    static void globalDeinit() { delete m_instance; };

    bool createDBConnection();

    // 添加数据
    bool addFeature(const FeatureData &featureData);
    bool addFeature(const QString &featureID, const QByteArray &feature, const QString &featureName,
                    const QString &IID, const QString &userName,
                    const QString &idVendor, const QString &idProduct,
                    const int &deviceType, const QString &deviceSerialNumber,
                    const int &authType);

    // 删除数据
    bool deleteFeature(const QString &featureID);
    bool deleteFearureByUserName(const QString &userName);
    bool deleteFearureByIID(const QString &IID);

    // 获取数据
    QList<QByteArray> getFeature();
    QByteArray getFeature(const QString &featureID);
    QList<QByteArray> getFeature(const QString &idVendor, const QString &idProduct, int deviceType, const QString &deviceSerialNumber);
    QStringList getFeatureID();
    QString getFeatureID(QByteArray feature);
    QStringList getFeatureID(const QString &idVendor, const QString &idProduct, int deviceType, const QString &deviceSerialNumber);
    FeatureData getFeatureData(const QString &featureID);

    QStringList getIID(const QString &userName);
    QStringList getIID(const QString &userName, const int &authType);
    QStringList getFeatureID(const QString &userName, const int &authType);
    QString getUserNameByFetureID(const QString &featureID);
    QString getUserNameByIID(const QString &iid);
    QString getFeatureNameByIID(const QString &iid);
    QString getFetureIDByIID(const QString &iid);

    // 更新数据
    bool updateFeatureNameByIID(const QString &iid, const QString &featureName);

private:
    void
    init();

private:
    static FeatureDB *m_instance;
};
}  // namespace Kiran
