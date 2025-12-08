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