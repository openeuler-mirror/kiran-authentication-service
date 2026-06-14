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

#include "udev-monitor.h"

namespace Kiran
{
UdevMonitor::UdevMonitor(QObject* parent) : QObject(parent)
{
    init();
}

UdevMonitor::~UdevMonitor()
{
    udev_monitor_unref(m_monitor);
    udev_unref(m_udev);
}

void UdevMonitor::init()
{
    m_udev = udev_new();
    // 创建一个新的monitor
    m_monitor = udev_monitor_new_from_netlink(m_udev, "udev");
    // 增加一个udev事件过滤器
    udev_monitor_filter_add_match_subsystem_devtype(m_monitor, "usb", nullptr);
    // 启动监控
    udev_monitor_enable_receiving(m_monitor);
    // 获取该监控的文件描述符，fd就代表了这个监控
    m_monitorFD = udev_monitor_get_fd(m_monitor);

    m_socketNotifierRead = QSharedPointer<QSocketNotifier>(new QSocketNotifier(m_monitorFD, QSocketNotifier::Read, this));
    connect(m_socketNotifierRead.data(), &QSocketNotifier::activated, this, &UdevMonitor::onSocketNotifierRead);
}

void UdevMonitor::onSocketNotifierRead(int socket)
{
    // 获取产生事件的设备映射
    struct udev_device* dev = udev_monitor_receive_device(m_monitor);
    if (!dev)
        return;

    // 获取事件并判断是否是插拔
    unsigned long long curNum = udev_device_get_devnum(dev);
    if (curNum <= 0)
    {
        udev_device_unref(dev);
        return;
    }

    /**
     * action 发生了以下操作：
     * add- 设备已连接到系统
     * remove- 设备与系统断开连接
     * change- 有关设备的某些内容已更改
     * move- 设备节点已移动、重命名或重新父级
     * bind
     * unbind
     */
    QString action = udev_device_get_action(dev);

    // 只有add和remove事件才会更新缓存信息
    if (action == "add")
    {
        QString idVendor = udev_device_get_sysattr_value(dev, "idVendor");
        QString idProduct = udev_device_get_sysattr_value(dev, "idProduct");
        QString devNode = udev_device_get_devnode(dev);
        Q_EMIT deviceAdded(idVendor, idProduct, devNode);
    }
    else if (action == "remove")
    {
        // remove 事件中 devNode 来自 uevent 消息体，仍然可用
        QString devNode = udev_device_get_devnode(dev);
        Q_EMIT deviceDeleted(devNode);
    }
    udev_device_unref(dev);
}
}  // namespace Kiran
