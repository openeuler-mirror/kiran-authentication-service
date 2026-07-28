/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-service is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     tangjie02 <tangjie02@kylinos.com.cn>
 */

#pragma once

#include <QJsonValue>
#include <QLocale>
#include <QString>
#include <string>

#include "kas-authentication-i.h"

namespace Kiran
{
class Utils
{
public:
    Utils() {};
    virtual ~Utils() {};

    /**
     * @brief 解析进程应使用的 LANG（环境变量 → /etc/locale.conf|/etc/sysconfig/i18n → 默认 zh_CN.UTF-8）
     * @return LANG 风格字符串，如 "zh_CN.UTF-8"；调用方不应释放
     * @note 供 D-Bus 激活等未继承会话 locale 的守护进程使用
     */
    static QString resolveLangEnv();

    /**
     * @brief 补齐进程 locale 环境并返回对应 QLocale
     * @return 解析后的 QLocale，供 QTranslator::load 使用
     */
    static QLocale setupProcessLocale();

    template <typename T>
    static QList<int> converEnumListToInt(QList<T> list);

    static QString GenerateIID(int32_t authType, const QString &dataID);

    static QString authModeEnum2Str(int authMode);
    static int authModeStr2Enum(const QString &authMode);

    static QString authTypeEnum2Str(int authType);
    static QString authTypeEnum2LocaleStr(int authType);
    static int authTypeStr2Enum(const QString &authType);

    static int32_t authType2DeviceType(int32_t authType);
    static int32_t authType2SoftDeviceType(int32_t authType);

    static QStringList authOrderEnum2Str(const QList<int> &authOrder);
    static QList<int> authOrderStr2Enum(const QStringList &authOrder);

    static QString fpEnrollResultEnum2Str(int32_t fpEnrollResult);
    static QString identifyResultEnum2Str(int32_t fpVerifyResult);

    static QJsonValue getValueFromJsonString(const QString &json, const QString &key);

    /** @brief QString → UTF-8 std::string，避免 Qt 5.6 toStdString() 依赖 C locale */
    static std::string qStringToUtf8StdString(const QString &text);

    /** @brief UTF-8 std::string → QString，与 qStringToUtf8StdString 配对 */
    static QString stdStringToQStringUtf8(const std::string &text);
};
}  // namespace Kiran