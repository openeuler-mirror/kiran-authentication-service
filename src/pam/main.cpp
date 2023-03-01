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

#include <pam_ext.h>
#include <pam_modules.h>
#include <qt5-log-i.h>
#include <syslog.h>
#include <QCoreApplication>
#include <QSharedPointer>
#include <QTranslator>
#include "src/pam/authentication-controller.h"
#include "src/pam/config-pam.h"
#include "src/pam/pam-args-parser.h"

extern "C" int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    bool isLocalApp = false;
    QCoreApplication *app = QCoreApplication::instance();
    if (!app)
    {
        /* 使用sudo运行时会调用setuid，QT程序会检查effective UserID和real UserID是否相同，默认情况下不相同程序直接退出。
           因此需要修改setuidAllowed属性来取消检查，不过这里可能会带来一些风险。文档描述如下：
           Qt is not an appropriate solution for setuid programs due to its large attack surface. 
           However some applications may be required to run in this manner for historical reasons. 
           This flag will prevent Qt from aborting the application when this is detected, 
           and must be set before a QCoreApplication instance is created.*/
        QCoreApplication::setSetuidAllowed(true);

        char programPath[] = KAS_INSTALL_LIBDIR "/security/" PROGRAM_NAME;
        int appArgc = 1;
        char *appArgv[2] = {programPath, NULL};
        app = new QCoreApplication(appArgc, (char **)appArgv);
        isLocalApp = true;
    }

    QTranslator translator;
    if (!translator.load(QLocale(), PROGRAM_NAME, ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        pam_syslog(pamh, LOG_ERR, "Load translator failed for %s.", PROGRAM_NAME);
    }
    else
    {
        app->installTranslator(&translator);
    }

    QStringList arguments;
    for (int i = 0; i < argc; ++i)
    {
        arguments.push_back(argv[i]);
    }

    auto controller = QSharedPointer<Kiran::AuthenticationController>::create(pamh, arguments);
    auto retval = controller->run();

    if (isLocalApp)
    {
        delete app;
    }

    pam_syslog(pamh, LOG_DEBUG, "auth result for %d.", retval);
    return retval;
}

extern "C" int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* Account Management API's */
extern "C" int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int, const char **)
{
    bool isLocalApp = false;
    QCoreApplication *app = QCoreApplication::instance();
    if (!app)
    {
        /* 使用sudo运行时会调用setuid，QT程序会检查effective UserID和real UserID是否相同，默认情况下不相同程序直接退出。
           因此需要修改setuidAllowed属性来取消检查，不过这里可能会带来一些风险。文档描述如下：
           Qt is not an appropriate solution for setuid programs due to its large attack surface. 
           However some applications may be required to run in this manner for historical reasons. 
           This flag will prevent Qt from aborting the application when this is detected, 
           and must be set before a QCoreApplication instance is created.*/
        QCoreApplication::setSetuidAllowed(true);

        char programPath[] = KAS_INSTALL_LIBDIR "/security/" PROGRAM_NAME;
        int appArgc = 1;
        char *appArgv[2] = {programPath, NULL};
        app = new QCoreApplication(appArgc, (char **)appArgv);
        isLocalApp = true;
    }

    QTranslator translator;
    if (!translator.load(QLocale(), PROGRAM_NAME, ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        pam_syslog(pamh, LOG_ERR, "Load translator failed for %s.", PROGRAM_NAME);
    }
    else
    {
        app->installTranslator(&translator);
    }

    QStringList arguments{KAP_ARG_ACTION_AUTH_SUCC};

    auto controller = QSharedPointer<Kiran::AuthenticationController>::create(pamh, arguments);
    auto retval = controller->run();

    if (isLocalApp)
    {
        delete app;
    }

    return retval;
}

/* Session Management API's */
extern "C" int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* Password Management API's */
extern "C" int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}
