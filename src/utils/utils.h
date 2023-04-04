/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd. 
 * kiran-session-manager is licensed under Mulan PSL v2.
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

#include <QString>
#include "kas-authentication-i.h"

namespace Kiran
{
class Utils
{
public:
    Utils(){};
    virtual ~Utils(){};

    template <typename T>
    static QList<int> converEnumListToInt(QList<T> list);

    static QString GenerateIID(int32_t authType, const QString &dataID);
    
    static QString authModeEnum2Str(int authMode);
    static int authModeStr2Enum(const QString &authMode);

    static QString authTypeEnum2Str(int authType);
    static int authTypeStr2Enum(const QString &authType);

    static int32_t authType2DeviceType(int32_t authType);
    static int32_t deviceType2AuthType(int32_t deviceType);

    static QStringList authOrderEnum2Str(const QList<int> &authOrder);
    static QList<int> authOrderStr2Enum(const QStringList &authOrder);

    static QString fpEnrollResultEnum2Str(int32_t fpEnrollResult);
    static QString identifyResultEnum2Str(int32_t fpVerifyResult);
};
}  // namespace Kiran