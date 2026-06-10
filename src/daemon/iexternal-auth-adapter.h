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
 *
 * Author:     licheng <licheng@kylinsec.com.cn>
 */

#pragma once

#include <QList>
#include <QObject>

/**
 * @brief 外部认证服务适配器纯虚接口
 *
 * 将原先硬编码在 AuthManager 中的 czht/kiran 判断逻辑
 * 抽象为统一接口，AuthManager 仅通过单指针 m_externalAuthAdapter
 * 调用，不再依赖具体服务实现。
 *
 * 继承 QObject，利用 Qt 父子对象树自动管理内存。
 */
class IExternalAuthServiceAdapter : public QObject
{
    Q_OBJECT
public:
    explicit IExternalAuthServiceAdapter(QObject *parent = nullptr) : QObject(parent) {}
    virtual ~IExternalAuthServiceAdapter() = default;

    /**
     * @brief 检查外部认证服务是否可用
     * @return 若对应的虚拟设备存在且 D-Bus 服务已注册返回 true
     */
    virtual bool isAvailable() = 0;

    /**
     * @brief 从外部认证服务获取支持的认证类型列表
     * @return 对应的 KADAuthType 列表
     */
    virtual QList<int> getAuthTypes() = 0;
};
