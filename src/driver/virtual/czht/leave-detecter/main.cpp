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

#include <qt5-log-i.h>
#include <QApplication>

#include "config.h"
#include "leave-detecter.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    if (klog_qt5_init(KAS_ZLOG_CONFIG_FILE, "kylinsec-session", PROJECT_NAME, "kiran-leave-detecter") != 0)
    {
        fprintf(stderr, "Failed to init kiran-log.");
    }

    KLOG_INFO() << "kiran-leave-detecter started";

    LeaveDetecter detecter;

    return app.exec();
}
