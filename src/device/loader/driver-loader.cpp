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

#include <dlfcn.h>
#include <qt5-log-i.h>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QLibrary>

#include "config.h"
#include "driver-i.h"
#include "driver-loader.h"

namespace Kiran
{
DriverLoader::DriverLoader(QObject *parent) : QObject(parent)
{
    init();
}

DriverLoader::~DriverLoader()
{
}

void DriverLoader::init()
{
    // 遍历DRIVER_DIR文件夹，加载所有so文件
    KLOG_INFO() << "load drivers from:" << KAS_AUTH_DRIVERSDIR;

    QStringList soFiles;
    QDirIterator it(KAS_AUTH_DRIVERSDIR,
                    QStringList() << "*.so",
                    QDir::Files,
                    QDirIterator::Subdirectories);  // 递归所有子目录
    while (it.hasNext())
    {
        soFiles.append(it.next());  // 获取文件的绝对路径
    }
    KLOG_INFO() << "find driver so:" << soFiles;

    for (const auto &file : soFiles)
    {
        auto driver = loadDriver(file);
        if (!driver)
        {
            continue;
        }

        switch (driver->getType())
        {
        case DRIVER_TYPE_FACE:
        case DRIVER_TYPE_FINGERPRINT:
        case DRIVER_TYPE_FINGERVEIN:
        case DRIVER_TYPE_IRIS:
        case DRIVER_TYPE_VOICEPRINT:
        case DRIVER_TYPE_UKEY:
            setupPhysicalDriver(file, driver);
            break;
        case DRIVER_TYPE_SOFT:
            m_softDrivers.append(file);
            break;
        default:
            break;
        }
    }
}

void DriverLoader::setupPhysicalDriver(const QString &file, const DriverPtr &driver)
{
    auto type = driver->getType();
    auto stdVidPids = driver->getSupportVidPid();

    QVector<QPair<QString, QString>> vidPids;
    for (const auto &pair : stdVidPids)
    {
        vidPids.append(qMakePair(
            QString::fromStdString(pair.first),
            QString::fromStdString(pair.second)));
    }

    m_physicalSupportDevices[file] = vidPids;
    m_physicalDriverInfos[file] = PhysicalDriverInfo{
        file,
        QString::fromStdString(driver->getDriverName()),
        type,
        vidPids};

    KLOG_INFO() << "driver:" << file
                << "driver name:" << QString::fromStdString(driver->getDriverName())
                << "type:" << getDriverTypeStr(type)
                << "support vidpids:" << vidPids;
}

DriverPtr DriverLoader::loadDriver(const QString &driverName)
{
    if (m_loadedDrivers.contains(driverName))
    {
        return m_loadedDrivers[driverName];
    }

    auto libPtr = new QLibrary(driverName);
    if (!libPtr)
    {
        return DriverPtr();
    }
    if (!libPtr->load())
    {
        delete libPtr;
        return DriverPtr();
    }

    auto createFunc = (CreateDriverFunc)libPtr->resolve("createDriver");
    if (!createFunc)
    {
        libPtr->unload();
        delete libPtr;
        return DriverPtr();
    }

    auto driver = DriverPtr(createFunc(), [libPtr](Driver *driver)
                            {
                                if (driver)
                                {
                                    delete driver;
                                }
                                if (libPtr)
                                {
                                    libPtr->unload();
                                    delete libPtr;
                                } });
    if (!driver)
    {
        libPtr->unload();
        delete libPtr;
        return DriverPtr();
    }

    m_loadedDrivers[driverName] = driver;
    return driver;
}

}  // namespace Kiran
