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
#include "driver-loader.h"
#include "driver/driver.h"
#include "driver/physical-driver.h"
#include "driver/ukey-driver.h"

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
    for (auto &file : soFiles)
    {
        auto driver = loadDriver(file);
        if (driver)
        {
            switch (driver->getType())
            {
            case DRIVER_TYPE_Face:
            case DRIVER_TYPE_FingerPrint:
            case DRIVER_TYPE_FingerVein:
            case DRIVER_TYPE_Iris:
            case DRIVER_TYPE_VoicePrint:
            case DRIVER_TYPE_UKey:
            {
                auto type = driver->getType();
                auto vidPids = ((PhysicalDriver *)driver.data())->getSupportVidPid();
                m_physicalSupportDevices[file] = vidPids;
                m_physicalDriverInfos[file] = PhysicalDriverInfo{file, driver->getDriverName(), type, vidPids};

                KLOG_INFO() << "driver:" << file << "driver name:" << driver->getDriverName() << "type:" << getDriverTypeStr(type) << "support vidpids:" << vidPids;

                // if (type == DRIVER_TYPE_UKey)
                // {
                //     KLOG_INFO() << "ukey online serial:" << ((UKeyDriver *)driver.data())->getOnlineSerials();
                // }
            }
            break;
            case DRIVER_TYPE_Virtual_Face:
            case DRIVER_TYPE_Virtual_Code:
            {
                m_virtualDrivers.append(file);
            }

            break;
            default:
                break;
            }
        }
    }
}

DriverPtr DriverLoader::loadDriver(const QString &driverName)
{
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
                                }
                            });
    if (!driver)
    {
        libPtr->unload();
        delete libPtr;
        return DriverPtr();
    }

    return driver;
}

}  // namespace Kiran
