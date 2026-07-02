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

#include <pam_ext.h>
#include <pam_modules.h>
#include <qt5-log-i.h>
#include <syslog.h>
#include <unistd.h>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QLocale>
#include <QSet>
#include <QSharedPointer>
#include <QTextCodec>
#include <QTranslator>
#include <clocale>

#include "authentication-controller.h"
#include "config-pam.h"
#include "pam-args-parser.h"

static const QSet<QString> supportedServiceName = {
    "lightdm",
    "kiran-screensaver",
    "polkit-1",
    "sudo",
    "gdm-password",
    "gnome-screensaver",
    "sshd"};

QString get_pam_service(pam_handle_t *pamh)
{
    const char *value = nullptr;
    int res = pam_get_item(pamh, PAM_SERVICE, (const void **)&value);
    if (res != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "%s failed.", __FUNCTION__);
        return QString();
    }
    return QString(value);
}

void put_env_qt_no_glib(pam_handle_t *pamh)
{
    auto value = get_pam_service(pamh);
    if (value == "gnome-screensaver" || value == "gdm-password")
    {
        pam_syslog(pamh, LOG_INFO, "put env QT_NO_GLIB for %s", value.toStdString().c_str());
        // 兼容gnome程序，在gnome程序下会存在事件冲突
        qputenv("QT_NO_GLIB", "1");
    }
}

static QString resolve_lang_env(pam_handle_t *pamh)
{
    const char *envNames[] = {"LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"};
    for (const char *envName : envNames)
    {
        const char *pamValue = pam_getenv(pamh, envName);
        if (pamValue && pamValue[0])
        {
            return QString::fromUtf8(pamValue);
        }

        const QByteArray value = qgetenv(envName);
        if (!value.isEmpty())
        {
            return QString::fromUtf8(value);
        }
    }

    const QStringList configFiles = {
        QStringLiteral("/etc/locale.conf"),
        QStringLiteral("/etc/sysconfig/i18n"),
    };
    for (const QString &configFile : configFiles)
    {
        QFile file(configFile);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            continue;
        }

        while (!file.atEnd())
        {
            const QString line = QString::fromUtf8(file.readLine()).trimmed();
            if (line.startsWith('#') || !line.startsWith(QStringLiteral("LANG=")))
            {
                continue;
            }
            return line.mid(5).trimmed().remove('"');
        }
    }

    return QStringLiteral("zh_CN.UTF-8");
}

static QLocale setup_pam_locale(pam_handle_t *pamh)
{
    const QString lang = resolve_lang_env(pamh);
    qputenv("LANG", lang.toUtf8());
    qputenv("LC_CTYPE", lang.toUtf8());
    setlocale(LC_ALL, "");

    if (lang.contains(QStringLiteral("UTF-8"), Qt::CaseInsensitive) ||
        lang.contains(QStringLiteral("utf8"), Qt::CaseInsensitive))
    {
        QTextCodec::setCodecForLocale(QTextCodec::codecForName("UTF-8"));
    }

    const QLocale locale(lang);
    const QTextCodec *codec = QTextCodec::codecForLocale();
    pam_syslog(pamh, LOG_DEBUG, "Resolved locale: lang=%s locale=%s codec=%s",
               lang.toUtf8().constData(), locale.name().toUtf8().constData(),
               codec ? codec->name().constData() : "null");
    return locale;
}

static bool load_pam_translator(QTranslator &translator, pam_handle_t *pamh,
                                const QLocale &locale)
{
    if (translator.load(locale, PROGRAM_NAME, ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        return true;
    }

    return false;
}

static void log_translator_load_failure(pam_handle_t *pamh, const QLocale &locale)
{
    pam_syslog(pamh, LOG_ERR,
               "Load translator failed for %s, locale=%s language=%s country=%s bcp47=%s",
               PROGRAM_NAME,
               locale.name().toUtf8().constData(),
               QLocale::languageToString(locale.language()).toUtf8().constData(),
               QLocale::countryToString(locale.country()).toUtf8().constData(),
               locale.bcp47Name().toUtf8().constData());
    pam_syslog(pamh, LOG_ERR, "Translation dir: %s uid=%d euid=%d",
               KAS_INSTALL_TRANSLATIONDIR, getuid(), geteuid());

    const char *envNames[] = {"LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"};
    for (const char *envName : envNames)
    {
        const QByteArray value = qgetenv(envName);
        pam_syslog(pamh, LOG_ERR, "env %s=%s", envName,
                   value.isEmpty() ? "(unset)" : value.constData());
    }

    const QStringList uiLanguages = locale.uiLanguages();
    pam_syslog(pamh, LOG_ERR, "uiLanguages: %s",
               uiLanguages.isEmpty() ? "(none)" : uiLanguages.join(',').toUtf8().constData());

    QDir transDir(QStringLiteral(KAS_INSTALL_TRANSLATIONDIR));
    if (!transDir.exists())
    {
        pam_syslog(pamh, LOG_ERR, "Translation directory does not exist: %s",
                   KAS_INSTALL_TRANSLATIONDIR);
        return;
    }

    const QStringList entries = transDir.entryList(
        QStringList() << QStringLiteral(PROGRAM_NAME "*.qm"), QDir::Files);
    if (entries.isEmpty())
    {
        pam_syslog(pamh, LOG_ERR, "No %s*.qm files in %s", PROGRAM_NAME,
                   KAS_INSTALL_TRANSLATIONDIR);
        return;
    }

    for (const QString &entry : entries)
    {
        pam_syslog(pamh, LOG_ERR, "Available translation: %s/%s",
                   KAS_INSTALL_TRANSLATIONDIR, entry.toUtf8().constData());
    }
}

static void install_pam_translator(pam_handle_t *pamh, QCoreApplication *app,
                                   QTranslator &translator, const QLocale &locale)
{
    if (load_pam_translator(translator, pamh, locale))
    {
        app->installTranslator(&translator);
        return;
    }

    log_translator_load_failure(pamh, locale);
}

// 通过PAM句柄获取生物认证是否支持该PAM服务
bool pam_service_is_support(pam_handle_t *pamh)
{
    auto value = get_pam_service(pamh);
    pam_syslog(pamh, LOG_INFO, "pam service: %s", value.toStdString().c_str());

    return supportedServiceName.contains(value);
}

extern "C" int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    if (!pam_service_is_support(pamh))
    {
        pam_syslog(pamh, LOG_DEBUG, PROGRAM_NAME " isn't support!, ignore");
        return PAM_IGNORE;
    }

    // 调用QCoreApplication前，设置QT_NO_GLIB环境变量
    put_env_qt_no_glib(pamh);

    const QLocale locale = setup_pam_locale(pamh);

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
    install_pam_translator(pamh, app, translator, locale);

    QStringList arguments;
    for (int i = 0; i < argc; ++i)
    {
        arguments.push_back(argv[i]);
    }

    pam_syslog(pamh, LOG_DEBUG, "arg:%s.", arguments.count() ? arguments.first().toStdString().c_str() : "null");

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
    if (!pam_service_is_support(pamh))
    {
        pam_syslog(pamh, LOG_DEBUG, PROGRAM_NAME " isn't support!, ignore");
        return PAM_IGNORE;
    }

    // 调用QCoreApplication前，设置QT_NO_GLIB环境变量
    put_env_qt_no_glib(pamh);

    const QLocale locale = setup_pam_locale(pamh);

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
    install_pam_translator(pamh, app, translator, locale);

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
