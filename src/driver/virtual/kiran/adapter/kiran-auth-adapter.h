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

#include "src/daemon/iexternal-auth-adapter.h"

/**
 * @brief Kiran 外部认证服务适配器
 *
 * 对接 kiran-face-dbus-service，实现 IExternalAuthServiceAdapter 接口。
 * 仅检查 VIRTUAL_FACE 和 VIRTUAL_CODE 设备（不支持 VIRTUAL_CODE_NO_CAMERA），
 * work_mode 解析采用位判断方式（C5）。
 */
class KiranAuthAdapter : public IExternalAuthServiceAdapter
{
public:
    explicit KiranAuthAdapter(QObject *parent = nullptr) : IExternalAuthServiceAdapter(parent) {}

    /**
     * @brief 检查 Kiran 人脸服务是否可用
     * @details 检查 VIRTUAL_FACE 和 VIRTUAL_CODE 虚拟设备是否存在，
     *          以及 com.kiran.face.service D-Bus 服务是否已注册
     * @return 若设备存在且 D-Bus 服务已注册返回 true
     */
    bool isAvailable() override;

    /**
     * @brief 从 Kiran 人脸服务获取认证类型列表
     * @details 调用 com.kiran.face.service 的 GetWorkMode D-Bus 接口，
     *          解析 JSON 返回的 work_mode 位标志字段，按位映射为 KADAuthType 列表
     * @return 认证类型列表
     */
    QList<int> getAuthTypes() override;
};
