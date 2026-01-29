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

#include <QComboBox>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDebug>
#include <QFile>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QListView>
#include <QPushButton>
#include <QSpacerItem>
#include <QSpinBox>
#include <QStyledItemDelegate>
#include <QVBoxLayout>

#include "config.h"
#include "czht-define.h"
#include "gen-code-dialog.h"

GenCodeDialog::GenCodeDialog(QWidget *parent)
    : QDialog(parent), m_applyPage(nullptr), m_resultPage(nullptr), m_resultLabel(nullptr), m_confirmBtn(nullptr), m_closeBtn(nullptr), m_spin(nullptr), m_combo(nullptr)
{
    setWindowTitle(tr("Request Authorization Code"));
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    init();
}

void GenCodeDialog::onApplyClicked()
{
    QDBusInterface *iface = new QDBusInterface(DBUS_INTERFACE, DBUS_PATH, DBUS_INTERFACE, QDBusConnection::systemBus(), this);
    if (!iface->isValid())
    {
        showResultPage(tr("Failed to request authorization code, please check if the face service (com.czht.face.daemon) is running"));
        return;
    }

    int expires_in = m_spin->value();
    if (m_combo->currentIndex() == 1)
    {
        expires_in *= 24;  // day
    }
    else if (m_combo->currentIndex() == 2)
    {
        expires_in *= 24;  // week
        expires_in *= 7;
    }
    else if (m_combo->currentIndex() == 3)
    {
        expires_in *= 24;  // month
        expires_in *= 30;
    }
    QJsonObject jsonObj;
    jsonObj.insert("business_id", BUSINESS_ID);
    jsonObj.insert("expires_in", expires_in);
    QJsonDocument jsonDoc(jsonObj);
    QString jsonStr = jsonDoc.toJson();
    qInfo() << "DBus call CodeGen with args:" << jsonStr;
    QDBusReply<QString> reply = iface->call("CodeGen", jsonStr);
    if (reply.isValid())
    {
        jsonDoc = QJsonDocument::fromJson(reply.value().toUtf8());
        jsonObj = jsonDoc.object();
        int error_code = jsonObj.value("code").toInt();
        if (error_code != CZHT_SUCCESS)
        {
            showResultPage(tr("Failed to request authorization code: %1").arg(getCZHTErrorMsg(error_code)));
        }
        else
        {
            showResultPage(tr("Request authorization code successfully, please wait for the SMS notification"));
        }
    }
    else
    {
        showResultPage(tr("Failed to request authorization code, please try again, %1").arg(reply.error().message()));
    }
    delete iface;
}

void GenCodeDialog::onConfirmClicked()
{
    close();
}

void GenCodeDialog::init()
{
    // 创建标题栏区域，包含关闭按钮
    auto *titleBar = new QWidget(this);
    auto *titleLayout = new QHBoxLayout(titleBar);
    titleLayout->setContentsMargins(0, 0, 0, 0);
    titleLayout->addStretch();  // 左侧弹性空间
    m_closeBtn = new QPushButton(titleBar);
    m_closeBtn->setObjectName("closeButton");
    m_closeBtn->setFixedSize(30, 30);
    m_closeBtn->setIcon(QIcon(":/icons/window-close-symbolic.svg"));
    m_closeBtn->setIconSize(QSize(16, 16));
    titleLayout->addWidget(m_closeBtn);
    connect(m_closeBtn, &QPushButton::clicked, this, &GenCodeDialog::close);

    createApplyPage();
    createResultPage();
    m_resultPage->hide();

    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);
    mainLayout->addWidget(titleBar);
    mainLayout->addWidget(m_applyPage);
    mainLayout->addWidget(m_resultPage);

    applyQss();
}

void GenCodeDialog::createApplyPage()
{
    m_applyPage = new QWidget(this);
    auto *label = new QLabel(tr("Authorization code request duration"), m_applyPage);
    m_spin = new QSpinBox(m_applyPage);
    m_spin->setRange(1, 9999);
    m_spin->setFixedHeight(30);
    m_combo = new QComboBox(m_applyPage);
    m_combo->addItems({tr("hour"), tr("day"), tr("week"), tr("month")});
    m_combo->setFixedHeight(30);
    auto delegate = new QStyledItemDelegate(this);
    m_combo->setItemDelegate(delegate);

    auto *btn = new QPushButton(tr("request"), m_applyPage);
    auto *labelTooltip = new QLabel(tr("please look at camera when click \"request\" button"), m_applyPage);

    auto *hl = new QHBoxLayout;
    hl->addWidget(m_spin);
    hl->addWidget(m_combo);

    auto *layout = new QVBoxLayout(m_applyPage);
    layout->addWidget(label);
    layout->addLayout(hl);
    layout->addWidget(btn);
    layout->addWidget(labelTooltip);

    connect(btn, &QPushButton::clicked, this, &GenCodeDialog::onApplyClicked);
}

void GenCodeDialog::createResultPage()
{
    m_resultPage = new QWidget(this);
    m_resultLabel = new QTextBrowser(m_resultPage);
    // m_resultLabel->setWordWrap(true);
    // m_resultLabel->setAlignment(Qt::AlignCenter);
    m_confirmBtn = new QPushButton(tr("Confirm"), m_resultPage);

    auto *layout = new QVBoxLayout(m_resultPage);
    layout->addWidget(m_resultLabel);
    layout->addWidget(m_confirmBtn);

    connect(m_confirmBtn, &QPushButton::clicked, this, &GenCodeDialog::onConfirmClicked);
}

void GenCodeDialog::showResultPage(const QString &message)
{
    m_resultLabel->setText(message);
    m_applyPage->hide();
    m_resultPage->show();
}

void GenCodeDialog::applyQss()
{
    // 从资源文件加载 QSS 样式
    QFile qssFile(":/styles/gen-code-dialog.qss");
    if (qssFile.open(QFile::ReadOnly | QFile::Text))
    {
        QString qss = QString::fromUtf8(qssFile.readAll());
        setStyleSheet(qss);
        qssFile.close();
    }
    else
    {
        // 如果资源文件加载失败，使用默认样式
        qWarning() << "Failed to load QSS file from resources";
    }
}