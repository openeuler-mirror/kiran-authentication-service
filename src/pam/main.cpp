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

extern "C" int pam_sm_authenticate(pam_handle_t *pamh, int flags, int,
                                   const char **)
{
    char programPath[] = KAS_INSTALL_LIBDIR "/security/" PROGRAM_NAME;
    int argc = 1;
    char *argv[2] = {programPath, NULL};
    bool isLocalApp = false;
    QCoreApplication *app = QCoreApplication::instance();
    if (!app)
    {
        app = new QCoreApplication(argc, (char **)argv);
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

    auto controller = QSharedPointer<Kiran::AuthenticationController>::create(pamh);
    auto retval = controller->run();

    if (isLocalApp)
    {
        delete app;
    }

    return retval;
}

extern "C" int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* Account Management API's */
extern "C" int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
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
