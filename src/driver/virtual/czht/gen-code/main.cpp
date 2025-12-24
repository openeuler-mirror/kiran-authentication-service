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

#include <QApplication>
#include <QFileInfo>
#include <QTranslator>

#include "config.h"
#include "gen-code-dialog.h"

int main(int argc, char *argv[])
{
    auto argv0 = QFileInfo(argv[0]);
    auto programName = argv0.baseName();
    QCoreApplication::setApplicationName(programName);
    QCoreApplication::setApplicationVersion(PROJECT_VERSION);

    QApplication app(argc, argv);

    QTranslator translator;
    if (translator.load(QLocale(), qAppName(), ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        app.installTranslator(&translator);
    }

    GenCodeDialog dlg;
    // 使用 exec() 显示模态对话框，会阻塞直到对话框关闭
    dlg.exec();
    return 0;
}