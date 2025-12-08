#include <QComboBox>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDebug>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QPushButton>
#include <QSpacerItem>
#include <QSpinBox>
#include <QVBoxLayout>

#include "../../czht-error.h"
#include "config.h"
#include "gen-code-dialog.h"

static const QString DBUS_INTERFACE = "com.czht.face.daemon";
static const QString DBUS_PATH = "/com/czht/face/daemon";

GenCodeDialog::GenCodeDialog(QWidget *parent)
    : QDialog(parent), m_applyPage(nullptr), m_resultPage(nullptr), m_resultLabel(nullptr), m_confirmBtn(nullptr), m_closeBtn(nullptr), m_spin(nullptr), m_combo(nullptr)
{
    setWindowTitle(tr("Request Authorization Code"));
    // setWindowFlags((windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowStaysOnTopHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint);
    setWindowFlags(Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
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
        expires_in *= 24;  //day
    }
    else if (m_combo->currentIndex() == 2)
    {
        expires_in *= 24;  //week
        expires_in *= 7;
    }
    else if (m_combo->currentIndex() == 3)
    {
        expires_in *= 24;  //month
        expires_in *= 30;
    }
    QJsonObject jsonObj;
    jsonObj.insert("business_id", "KylinsecOS");
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
    m_closeBtn = new QPushButton("×", titleBar);
    m_closeBtn->setFixedSize(30, 30);
    m_closeBtn->setStyleSheet(
        "QPushButton {"
        "    background-color: transparent;"
        "    color: #333;"
        "    border: none;"
        "    font-size: 20px;"
        "    font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "    background-color: #f0f0f0;"
        "    border-radius: 3px;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #e0e0e0;"
        "}");
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
    m_combo = new QComboBox(m_applyPage);
    m_combo->addItems({tr("hour"), tr("day"), tr("week"), tr("month")});
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
    // 按钮、下拉框、输入框、标签等控件的样式
    QString qss = QString(
        "QPushButton {"
        "    background-color: #4CAF50;"
        "    color: white;"
        "    border: none;"
        "    padding: 10px 20px;"
        "    border-radius: 5px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #45a049;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #388e3c;"
        "}"
        "QComboBox {"
        "    background-color: #ffffff;"
        "    border: 1px solid #ccc;"
        "    padding: 5px;"
        "    border-radius: 5px;"
        "}"
        "QComboBox:hover {"
        "    background-color: #45a049;"
        "}"
        "QComboBox:pressed {"
        "    background-color: #388e3c;"
        "}"
        "QComboBox:focus {"
        "    background-color: #4CAF50;"
        "}"
        "QSpinBox {"
        "    background-color: #ffffff;"
        "    border: 1px solid #ccc;"
        "    padding: 5px;"
        "    border-radius: 5px;"
        "}"
        "QSpinBox:hover {"
        "    background-color: #45a049;"
        "}"
        "QSpinBox:pressed {"
        "    background-color: #388e3c;"
        "}"
        "QSpinBox:focus {"
        "    background-color: #4CAF50;"
        "}"
        "QLabel {"
        "    color: #333;"
        "    font-size: 14px;"
        "    font-weight: bold;"
        "}"
        "QDialog {"
        "    background-color: #ffffff;"
        "    border: 1px solid #ccc;"
        "    padding: 10px;"
        "    border-radius: 5px;"
        "}");
    setStyleSheet(qss);
}