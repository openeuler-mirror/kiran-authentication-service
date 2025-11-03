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
#include <QDBusMessage>

#include "auth_device_adaptor.h"
#include "driver/ukey-driver.h"
#include "kas-authentication-i.h"
#include "lib/feature-data.h"
#include "lib/feature-db.h"
#include "lib/utils.h"
#include "ukey-device.h"

#define SAR_OK 0x00000000
#define SAR_PIN_INCORRECT 0x0A000024
#define SAR_PIN_LOCKED 0x0A000025
#define SAR_PIN_INVALID 0x0A000026
#define SAR_PIN_LEN_RANGE 0x0A000027

namespace Kiran
{
UkeyDevice::UkeyDevice(const QString& vid, const QString& pid, DriverPtr driver, QObject* parent) : Device(driver, parent)
{
    KLOG_INFO() << "UkeyDevice::UkeyDevice"
                << "vid:" << vid << "pid:" << pid << "deviceID:" << deviceID();
    m_driver = driver.staticCast<UKeyDriver>();
    m_idVendor = vid;
    m_idProduct = pid;
}

UkeyDevice::~UkeyDevice()
{
}
DeviceType UkeyDevice::deviceType()
{
    return DEVICE_TYPE_UKey;
}

void UkeyDevice::EnrollStart(const QString& extraInfo)
{
    QString message;
    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        message = tr("Device Busy");
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL, message);
        KLOG_INFO() << message;
        return;
    }
    m_status = DEVICE_STATUS_DOING_ENROLL;

    //    auto replyMessage = QDBusMessage().createReply();
    //    QDBusConnection::systemBus().send(replyMessage);

    KLOG_INFO() << "EnrollStart";

    QJsonValue ukeyValue = Utils::getValueFromJsonString(extraInfo, AUTH_DEVICE_JSON_KEY_UKEY);
    auto jsonObject = ukeyValue.toObject();
    QString pin = jsonObject.value(AUTH_DEVICE_JSON_KEY_PIN).toString();
    QString serialNumber = jsonObject.value(AUTH_DEVICE_JSON_KEY_SERIAL_NUMBER).toString();
    // 如果传过来的序列号为空，则使用插入设备的第一个序列号
    if (serialNumber.isEmpty())
    {
        serialNumber = m_driver->getOnlineSerials().first();
    }

    do
    {
        if (pin.isEmpty())
        {
            QString message = tr("The pin code cannot be empty!");
            Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL, message);
            KLOG_ERROR() << "The pin code cannot be empty!";
            break;
        }

        if (isExistBinding(serialNumber))
        {
            notifyEnrollProcess(ENROLL_PROCESS_REPEATED_ENROLL);
            break;
        }

        QByteArray pubKey;
        int ret = m_driver->enroll(pin, pubKey, serialNumber);
        if (ret != 0)
        {
            notifyEnrollProcess(ENROLL_PROCESS_FAIL, ret);
        }
        else
        {
            // 特征存储
            // NOTE: 这里没有传featureName、IID、userID
            auto type = deviceType();
            QString featureID = QCryptographicHash::hash(pubKey, QCryptographicHash::Md5).toHex();
            FeatureData data;
            data.feature = pubKey;
            data.featureID = featureID;
            data.idVendor = m_idVendor;
            data.idProduct = m_idProduct;
            data.deviceSerialNumber = serialNumber;
            data.deviceType = deviceType();
            notifyEnrollProcess(ENROLL_PROCESS_SUCCESS, SAR_OK, data);
        }

    } while (false);

    EnrollStop();
}
void UkeyDevice::EnrollStop()
{
    if (DEVICE_STATUS_DOING_ENROLL == deviceStatus())
    {
        m_status = DEVICE_STATUS_IDLE;
    }
}

void UkeyDevice::IdentifyStart(const QString& extraInfo)
{
    KLOG_INFO() << "UkeyDevice IdentifyStart";
    KLOG_INFO() << "extraInfo:" << extraInfo;

    if (DEVICE_STATUS_IDLE != deviceStatus())
    {
        QString message = tr("Device Busy");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        KLOG_INFO() << QString("%1, deviceID:%2").arg("Device Busy").arg(m_devId);
        return;
    }

    QStringList featureIDs;
    QJsonArray jsonArray = Utils::getValueFromJsonString(extraInfo, AUTH_DEVICE_JSON_KEY_FEATURE_IDS).toArray();
    if (!jsonArray.isEmpty())
    {
        QVariantList varList = jsonArray.toVariantList();
        for (auto var : varList)
        {
            featureIDs << var.toString();
        }
    }

    QString serialNumber = Utils::getValueFromJsonString(extraInfo, AUTH_DEVICE_JSON_KEY_SERIAL_NUMBER).toString();
    if (serialNumber.isEmpty())
    {
        serialNumber = m_driver->getOnlineSerials().first();
    }

    // 对于UKey而言，一个UKey设备只能绑定到一个用户（设备内私钥只有一份，公钥是否可以生成多个？），所以featuresThatNeedToIdentify大小应该为1
    QList<QByteArray> featuresThatNeedToIdentify;
    if (featureIDs.isEmpty())
    {
        featuresThatNeedToIdentify = FeatureDB::getInstance()->getFeature(m_idVendor, m_idProduct, deviceType(), serialNumber);
    }
    else
    {
        for (auto featureID : featureIDs)
        {
            featuresThatNeedToIdentify << FeatureDB::getInstance()->getFeature(featureID);
        }
    }

    if (featuresThatNeedToIdentify.count() == 0)
    {
        KLOG_INFO() << "no found feature id";
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, tr("identify fail!"));
        return;
    }

    m_status = DEVICE_STATUS_DOING_IDENTIFY;
    //    auto replyMessage = QDBusMessage().createReply();
    //    QDBusConnection::systemBus().send(replyMessage);

    QJsonValue ukeyValue = Utils::getValueFromJsonString(extraInfo, AUTH_DEVICE_JSON_KEY_UKEY);
    auto jsonObject = ukeyValue.toObject();
    QString pin = jsonObject.value(AUTH_DEVICE_JSON_KEY_PIN).toString();
    do
    {
        if (pin.isEmpty())
        {
            QString message = tr("The pin code cannot be empty!");
            Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
            KLOG_INFO() << "The pin code cannot be empty!";
            break;
        }

        int ret = 0;
        int j = 0;
        QByteArray feature;
        for (; j < featuresThatNeedToIdentify.count(); j++)
        {
            feature = featuresThatNeedToIdentify.value(j);
            ret = m_driver->identify(pin, feature, serialNumber);
            if (0 == ret)
            {
                break;
            }
        }
        if (0 != ret)
        {
            KLOG_ERROR() << "identify fail:" << m_driver->getErrorMsg(ret);
            notifyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH, ret);
        }
        else
        {
            QString featureID = FeatureDB::getInstance()->getFeatureID(feature);
            KLOG_INFO() << "identify success";
            notifyIdentifyProcess(IDENTIFY_PROCESS_MACTCH, ret, featureID);
        }

    } while (false);

    IdentifyStop();
}

void UkeyDevice::IdentifyStop()
{
    if (DEVICE_STATUS_DOING_IDENTIFY == deviceStatus())
    {
        m_status = DEVICE_STATUS_IDLE;
    }
}

QStringList UkeyDevice::GetFeatureIDList()
{
    auto serialNumber = m_driver->getOnlineSerials().first();

    QStringList featureIDs = FeatureDB::getInstance()->getFeatureID(m_idVendor, m_idProduct, deviceType(), serialNumber);
    return featureIDs;
}

void UkeyDevice::notifyEnrollProcess(EnrollProcess process, int error, const FeatureData& featureData)
{
    QString reason;
    // 目前只需要返回有关pin码的错误信息
    reason = getPinErrorReson(error);
    if (error != SAR_OK)
    {
        KLOG_DEBUG() << "Ukey Error Reason:" << m_driver->getErrorMsg(error);
    }

    QString message = tr("Binding user failed!");
    switch (process)
    {
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed binding user");
        Q_EMIT m_dbusAdaptor->EnrollStatus(structToJsonString<FeatureData>(featureData), 100, ENROLL_STATUS_COMPLETE, message);
        break;
    case ENROLL_PROCESS_FAIL:
        if (!reason.isEmpty())
        {
            message.append(reason);
        }
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message.append(tr("UKey has been bound"));
        Q_EMIT m_dbusAdaptor->EnrollStatus({}, 0, ENROLL_STATUS_FAIL, message);
        break;
    default:
        break;
    }
    if (!message.isEmpty())
    {
        if (!featureData.featureID.isEmpty())
        {
            KLOG_DEBUG() << QString("%1, feature id:%2").arg(message).arg(featureData.featureID);
        }
        else
        {
            KLOG_DEBUG() << message;
        }
    }
}

void UkeyDevice::notifyIdentifyProcess(IdentifyProcess process, int error, const QString& featureID)
{
    QString message, reason;
    reason = getPinErrorReson(error);

    switch (process)
    {
    case IDENTIFY_PROCESS_NO_MATCH:
        KLOG_INFO() << "identify ukey fail";
        message = tr("identify fail!");
        // 目前只需要返回有关pin码的错误信息
        if (!reason.isEmpty())
        {
            message.append(reason);
        }
        // message.append(QString(tr(",remaining retry count: %1")).arg(m_retryCount));
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("identify ukey success");
        KLOG_INFO() << "identify ukey success";
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_STATUS_MATCH, message);
        break;
    default:
        break;
    }

    if (!message.isEmpty())
    {
        KLOG_DEBUG() << QString("%1, feature id:%2").arg(message).arg(featureID);
    }
}

QString UkeyDevice::getPinErrorReson(int error)
{
    QString reason;
    if (error == SAR_OK)
    {
        return reason;
    }
    // 目前只需要返回有关pin码的错误信息
    switch (error)
    {
    case SAR_PIN_INCORRECT:
        reason = tr("pin incorrect");
        break;
    case SAR_PIN_LOCKED:
        reason = tr("pin locked");
        break;
    case SAR_PIN_INVALID:
        reason = tr("invalid pin");
        break;
    case SAR_PIN_LEN_RANGE:
        reason = tr("invalid pin length");
        break;
    default:
        break;
    }
    return reason;
}

bool UkeyDevice::isExistBinding(const QString& serialNumber)
{
    QStringList featureIDs = FeatureDB::getInstance()->getFeatureID(m_idVendor, m_idProduct, deviceType(), serialNumber);
    KLOG_INFO() << "Existing Binding featureIDs:" << featureIDs;
    for (auto id : featureIDs)
    {
        FeatureData data = FeatureDB::getInstance()->getFeatureData(id);
        if (data.deviceSerialNumber == serialNumber)
        {
            KLOG_DEBUG() << QString("Exist Binding: feature id:%1, device serial number: %2").arg(id).arg(serialNumber);
            return true;
        }
    }
    return false;
}

}  // namespace Kiran
