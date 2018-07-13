#ifndef STORE_EXAMPLE_MAIN_WIDGET_H
#define STORE_EXAMPLE_MAIN_WIDGET_H

#include <QWidget>

namespace Ui {
  class StoreExampleMainWidget;
}

class StoreExampleMainWidget : public QWidget
{
  Q_OBJECT

public:
  explicit StoreExampleMainWidget(QWidget *parent = 0);
  ~StoreExampleMainWidget();

private slots:
  void on_btnTranslateReceive_clicked();

private slots:
  void on_btnTranslateSend_clicked();

private slots:
  void on_radioButton_9_clicked();

private slots:
  void on_radioButton_10_clicked();

private slots:
  void on_btnTranslateHistory_clicked();

private slots:
  void on_btnUnReceived_clicked();

private slots:
  void on_btnAccountList_clicked();

private slots:
  void on_btnAccountBalance_clicked();

private slots:
  void on_btnPubKey2Addr_clicked();

private slots:
  void on_btnPriKey2PubKey_clicked();

private slots:
  void on_cmbTestPrivateKey_currentTextChanged(const QString &arg1);

private:
  Ui::StoreExampleMainWidget *ui;
  QStringList test_pri_key_list_;
};

#endif // STORE_EXAMPLE_MAIN_WIDGET_H
