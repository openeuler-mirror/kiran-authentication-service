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
 * @brief CZHT 外部认证服务适配器
 *
 * 将原 auth-manager 中的 czht 硬编码逻辑抽离至此，
 * 实现 IExternalAuthServiceAdapter 接口。
 */
class CzhtAuthAdapter : public IExternalAuthServiceAdapter
{
public:
    explicit CzhtAuthAdapter(QObject *parent = nullptr) : IExternalAuthServiceAdapter(parent) {}

    /**
     * @brief 检查 CZHT 人脸服务是否可用
     * @details 检查三类虚拟设备（FACE/CODE/CODE_NO_CAMERA）是否存在，
     *          以及 com.czht.face.daemon D-Bus 服务是否已注册
     * @return 若设备存在且 D-Bus 服务已注册返回 true
     */
    bool isAvailable() override;

    /**
     * @brief 从 CZHT 服务获取认证类型列表
     * @details 调用 CZHT 服务的 GetWorkMode D-Bus 接口，
     *          解析 JSON 返回的 work_mode 字段，按 switch-case 1-6 映射为 KADAuthType 列表
     * @return 认证类型列表
     */
    QList<int> getAuthTypes() override;
};
