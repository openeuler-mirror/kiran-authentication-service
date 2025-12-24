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
 
#pragma once

#include <QComboBox>
#include <QDialog>
#include <QPushButton>
#include <QSpinBox>
#include <QTextBrowser>
#include <QWidget>

class GenCodeDialog : public QDialog
{
    Q_OBJECT
public:
    GenCodeDialog(QWidget* parent = nullptr);

private slots:
    void onApplyClicked();
    void onConfirmClicked();

private:
    void init();
    void createApplyPage();
    void createResultPage();
    void showResultPage(const QString& message);
    void applyQss();

private:
    QWidget* m_applyPage;
    QWidget* m_resultPage;
    QTextBrowser* m_resultLabel;
    QPushButton* m_confirmBtn;
    QPushButton* m_closeBtn;
    QSpinBox* m_spin;
    QComboBox* m_combo;
};