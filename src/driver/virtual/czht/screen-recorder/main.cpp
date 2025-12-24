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
#include <QCoreApplication>

#include "config.h"
#include "screen-recorder.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    if (klog_qt5_init("", "kylinsec-system", PROJECT_NAME, "kiran-screen-recorder") != 0)
    {
        fprintf(stderr, "Failed to init kiran-log.");
    }
    KLOG_INFO() << "----------------------";

    // 获取第一个参数
    QString fileName = argc > 1 ? argv[1] : "";
    ScreenRecorder recorder;
    recorder.start(fileName);

    return app.exec();
}
