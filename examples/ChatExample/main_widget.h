#ifndef MAIN_WIDGET_H
#define MAIN_WIDGET_H

#include <QWidget>
#include <grpcpp/grpcpp.h>
#include <rpc/rpc.grpc.pb.h>
namespace Ui {
  class MainWidget;
}

class MainWidget : public QWidget
{
  Q_OBJECT

public:
  explicit MainWidget(QWidget *parent = 0);
  ~MainWidget();

private slots:
  void on_pushButton_2_clicked();

  void on_btnCheckBalance_clicked();

  void on_btnGetHistory_clicked();

  void on_btnGetWaitReceive_clicked();

  void on_btnGetLastUnitHash_clicked();

  void on_btnGetPublicKey_clicked();

  void on_btnGetSendUnitJson_clicked();

  void on_btnSendSendUnit_clicked();

  void on_btnGetReceiveUnitJson_clicked();

  void on_btnSendReceiveUnit_clicked();

private:
  Ui::MainWidget *ui;
  std::shared_ptr<grpc::Channel> channel_;
};

#endif // MAIN_WIDGET_H
