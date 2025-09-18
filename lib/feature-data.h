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

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QMetaProperty>
#include <QMetaType>
#include <QString>

// 特征数据结构体
struct FeatureData
{
    Q_GADGET
    Q_PROPERTY(QByteArray feature MEMBER feature)
    Q_PROPERTY(QString featureID MEMBER featureID)
    Q_PROPERTY(QString featureName MEMBER featureName)
    Q_PROPERTY(QString iid MEMBER iid)
    Q_PROPERTY(QString userName MEMBER userName)
    Q_PROPERTY(QString idVendor MEMBER idVendor)
    Q_PROPERTY(QString idProduct MEMBER idProduct)
    Q_PROPERTY(QString deviceSerialNumber MEMBER deviceSerialNumber)
    Q_PROPERTY(int deviceType MEMBER deviceType)
    Q_PROPERTY(int authType MEMBER authType)

public:
    QByteArray feature;
    QString featureID;
    QString featureName;
    QString iid;
    QString userName;
    QString idVendor;
    QString idProduct;
    QString deviceSerialNumber;
    int deviceType;
    int authType;
};

// struct -> QJsonObject
template <typename T>
inline QJsonObject structToJson(const T &obj) {
  QJsonObject json;
  const QMetaObject *metaObj = &T::staticMetaObject;
  for (int i = metaObj->propertyOffset(); i < metaObj->propertyCount(); ++i) {
    QMetaProperty prop = metaObj->property(i);
    QVariant value = prop.readOnGadget(&obj);

    // 仅对 QByteArray 做 base64
    if (prop.type() == QVariant::ByteArray) {
      QByteArray ba = value.toByteArray();
      json[prop.name()] = QString::fromUtf8(ba.toBase64());
    } else {
      json[prop.name()] = QJsonValue::fromVariant(value);
    }
  }
  return json;
}

// QJsonObject -> struct
template <typename T>
inline T jsonToStruct(const QJsonObject &json) {
  T obj;
  const QMetaObject *metaObj = &T::staticMetaObject;
  for (int i = metaObj->propertyOffset(); i < metaObj->propertyCount(); ++i) {
    QMetaProperty prop = metaObj->property(i);
    if (!json.contains(prop.name())) continue;

    QVariant value = json[prop.name()].toVariant();

    if (prop.type() == QVariant::ByteArray) {
      QByteArray ba = QByteArray::fromBase64(value.toString().toUtf8());
      prop.writeOnGadget(&obj, ba);
    } else {
      prop.writeOnGadget(&obj, value);
    }
  }
  return obj;
}

// 结构体 → JSON 字符串
template <typename T>
inline QString structToJsonString(
    const T &obj, QJsonDocument::JsonFormat format = QJsonDocument::Compact) {
  return QString::fromUtf8(QJsonDocument(structToJson(obj)).toJson(format));
}

// JSON 字符串 → 结构体
template <typename T>
inline T jsonStringToStruct(const QString &jsonStr) {
  QJsonParseError err;
  QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8(), &err);
  if (err.error != QJsonParseError::NoError || !doc.isObject()) {
    return T();  // 返回默认构造的对象
  }
  return jsonToStruct<T>(doc.object());
}