#include "main_widget.h"
#include "ui_main_widget.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QPlainTextEdit>
#include "assist_lib.h"
MainWidget::MainWidget(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::MainWidget)
{
  qRegisterMetaType<std::string>("std::string");
  ui->setupUi(this);
  channel_ = grpc::CreateChannel("localhost:50088",grpc::InsecureChannelCredentials());
  connect(this, SIGNAL(DoReceiveMessage(std::string,std::string)), this, SLOT(OnReceiveMessage(std::string,std::string)));
}

MainWidget::~MainWidget()
{
  delete ui;
}

void MainWidget::OnReceiveMessage(std::string pub_key, std::string msg)
{
  QString str;
  str = str + "pubkey:"+pub_key.c_str();
  str = str+"msg:"+msg.c_str();
  str+="\r\n";
  ui->edtChatLog->appendPlainText(str);
}

void MainWidget::on_pushButton_2_clicked()
{

}

void MainWidget::on_btnCheckBalance_clicked()
{
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::GetBalanceRequest request;
  ambr::rpc::GetBalanceReply responce;

  request.set_public_key(ui->edtGetBalancePubkey->text().toStdString());
  grpc::Status status = stub.GetBalance(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      ui->edtGetBalanceResult->setText(QString::fromStdString(responce.amount()));
    }else{
      ui->edtGetBalanceResult->setText(QString::fromStdString(responce.error_message()));
    }
  }
}

void MainWidget::on_btnGetHistory_clicked(){
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::GetHistoryRequest request;
  ambr::rpc::GetHistoryReply responce;

  request.set_public_key(ui->edtGetHistoryPublicKey->text().toStdString());
  grpc::Status status = stub.GetHistory(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      while(ui->tabGetHistory->rowCount())
        ui->tabGetHistory->removeRow(0);
      for(int i = 0; i < responce.items_size(); i++){
        ::ambr::rpc::HistoryItem item = responce.items(i);
        ui->tabGetHistory->insertRow(0);
        ui->tabGetHistory->setItem(0,0, new QTableWidgetItem(QString::fromStdString(item.type())));
        ui->tabGetHistory->setItem(0,1, new QTableWidgetItem(QString::fromStdString(item.amount())));
      }
    }
  }
}

void MainWidget::on_btnGetWaitReceive_clicked(){
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::GetWaitForReceiveUnitRequest request;
  ambr::rpc::GetWaitForReceiveUnitReply responce;

  request.set_public_key(ui->edtGetWaitReceivePublickey->text().toStdString());
  grpc::Status status = stub.GetWaitForReceiveUnit(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      while(ui->tabGetWaitReceive->rowCount())
        ui->tabGetWaitReceive->removeRow(0);
      for(int i = 0; i < responce.items_size(); i++){
        ::ambr::rpc::WaitForReceiveItem item = responce.items(i);
        ui->tabGetWaitReceive->insertRow(0);
        ui->tabGetWaitReceive->setItem(0,0, new QTableWidgetItem(QString::fromStdString(item.hash())));
        ui->tabGetWaitReceive->setItem(0,1, new QTableWidgetItem(QString::fromStdString(item.amount())));
      }
    }
  }
}

void MainWidget::on_btnGetLastUnitHash_clicked(){
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::GetLastUnitHashRequest request;
  ambr::rpc::GetLastUnitHashReplay responce;

  request.set_public_key(ui->edtGetLastUnitHashPublicKey->text().toStdString());
  grpc::Status status = stub.GetLastUnitHash(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      ui->edtGetLastUnitHash->setText(QString::fromStdString(responce.hash()));
    }else{
      ui->edtGetLastUnitHash->setText(QString::fromStdString(responce.error_message()));
    }
  }
}

void MainWidget::on_btnGetPublicKey_clicked(){
    char* data = GetPublicKeyByPrivateKey(ui->edtGetPublicKeyPrivate->text().toStdString().c_str());
    ui->edtGetPublicKeyResult->setText(data);
}

void MainWidget::on_btnGetSendUnitJson_clicked(){

  QString str = GetSendUnitJson(ui->edtGetSendUnitJsonPrivateKey->text().toStdString().c_str(),
                        ui->edtGetSendUnitJsonDest->text().toStdString().c_str(),
                        ui->edtGetSendUnitHash->text().toStdString().c_str(),
                        ui->edtGetSendUnitJsonBalance->text().toULongLong(),
                        ui->edtGetSendUnitJsonAmount->text().toULongLong());
  ui->edtGetSendUnitJsonResult->setPlainText(str);
}

void MainWidget::on_btnSendSendUnit_clicked(){
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::AddUnitRequest request;
  ambr::rpc::AddUnitReply responce;

  request.set_json(ui->edtSendSendUnit->toPlainText().toStdString());
  grpc::Status status = stub.AddSendUnitByJson(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      ui->edtSendSendUnit->setPlainText("OK");
    }else{
      ui->edtSendSendUnit->setPlainText(QString::fromStdString(responce.error_message()));
    }
  }
}

void MainWidget::on_btnGetReceiveUnitJson_clicked(){

  QString str = GetReceiveUnitJson(ui->edtGetReceiveUnitJsonPrivateKey->text().toStdString().c_str(),
                           ui->edtGetReceiveUnitJsonFrom->text().toStdString().c_str(),
                           ui->edtGetReceiveUnitJsonFromAmount->text().toULongLong(),
                           ui->edtGetReceiveUnitJsonLastHash->text().toStdString().c_str(),
                           ui->edtGetReceiveUnitJsonBalance->text().toULongLong());
  ui->edtGetReceiveUnitJsonResult->setPlainText(str);
}

void MainWidget::on_btnSendReceiveUnit_clicked(){
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::AddUnitRequest request;
  ambr::rpc::AddUnitReply responce;

  request.set_json(ui->edtSendReceiveUnit->toPlainText().toStdString());
  grpc::Status status = stub.AddReceiveUnitByJson(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      ui->edtSendReceiveUnit->setPlainText("OK");
    }else{
      ui->edtSendReceiveUnit->setPlainText(QString::fromStdString(responce.error_message()));
    }
  }
}
#include <QMessageBox>
void MainWidget::on_btnPubSendTrans_clicked(){
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::PubSendTransfRequest request;
  ambr::rpc::PubSendTransfReply responce;

  request.set_private_key(ui->edtPubSendTransPrivate->text().toStdString());
  request.set_dest_public(ui->edtPubSendTransDest->text().toStdString());
  request.set_amount(ui->edtPubSendTransAmount->text().toStdString());
  grpc::Status status = stub.PubSendTransf(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      QMessageBox::information(nullptr, "title", "OK");
    }else{
      QMessageBox::information(nullptr, "title", responce.error_message().c_str());
    }
  }
}

void MainWidget::on_btnPubReceiveTrans_clicked()
{
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::PubReceiveTransfRequest request;
  ambr::rpc::PubReceiveTransfReply responce;

  request.set_private_key(ui->edtPubReceiveTransPrivate->text().toStdString());
  request.set_from_hash(ui->edtPubReceiveTransFromHash->text().toStdString());
  grpc::Status status = stub.PubReceiveTransf(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      QMessageBox::information(nullptr, "title", "OK");
    }else{
      QMessageBox::information(nullptr, "title", responce.error_message().c_str());
    }
  }
}

void MainWidget::on_btnPubSendMessage_clicked()
{
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::PubSendMessageRequest request;
  ambr::rpc::PubSendMessageReply responce;

  request.set_private_key(ui->edtPubSendMessagePrivate->text().toStdString());
  request.set_message(ui->edtPubSendMessageMessage->text().toStdString());
  grpc::Status status = stub.PubSendMessage(&context, request, &responce);
  if(status.ok()){
    if(responce.result()){
      QMessageBox::information(nullptr, "title", "OK");
    }else{
      QMessageBox::information(nullptr, "title", responce.error_message().c_str());
    }
  }
}
#include <QPushButton>
#include <thread>
void MainWidget::on_btnChatStart_clicked()
{
    ui->btnChatStart->setEnabled(false);
    std::thread* thread = new std::thread(std::bind(&MainWidget::StreamChatThread, this));
}

void MainWidget::StreamChatThread()
{
  ambr::rpc::RpcInterface::Stub stub(channel_);
  grpc::ClientContext context;
  ambr::rpc::MessageStreamRequest request;
  ambr::rpc::MessageStreamReply responce;

  //request.set_private_key(ui->edtPubSendMessagePrivate->text().toStdString());
  //request.set_message(ui->edtPubSendMessageMessage->text().toStdString());
  std::unique_ptr< ::grpc::ClientReader< ::ambr::rpc::MessageStreamReply>> stream = stub.GetMessageStream(&context, request);
  ambr::rpc::MessageStreamReply amsg;
  while(stream->Read(&amsg)){
    emit DoReceiveMessage(amsg.public_key(), amsg.message());
  }
}
