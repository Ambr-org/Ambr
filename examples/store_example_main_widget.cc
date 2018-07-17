#include "store_example_main_widget.h"
#include "ui_store_example_main_widget.h"
#include <store/store_manager.h>
#include <unordered_map>

StoreExampleMainWidget::StoreExampleMainWidget(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::StoreExampleMainWidget)
{
  ui->setupUi(this);
  test_pri_key_list_.push_back("F49E1B9F671D0B244744E07289EA0807FAE09F8335F0C1B0629F1BF924CA64E1");
  test_pri_key_list_.push_back("29176270484F74852C5ABCBFEF26C4193FE4C2E4C522984D833329EDD502DC84");
  test_pri_key_list_.push_back("9812383BF3CE164A3D968186BEBA1CCFF299C9C59448A19BF3C0582336E01301");
  test_pri_key_list_.push_back("C56E273AE386A16846D5710F2B04DE75DE5D4DD086D15ABBFF0B184BC01F81C5");
  test_pri_key_list_.push_back("C99FC6C3EF33BAB82A8DC27C3D6C26D90DFF3FBE1EB7BA6996A88662A34E031E");
  test_pri_key_list_.push_back("158DA7D0ED279C29C0F60599E7009F000E4878C26D12E8031DFA7E93C13C0E88");
  test_pri_key_list_.push_back("1131372AAE12C73F25388E525B8664096A1FF1C79474E562A82537F80F91A337");
  test_pri_key_list_.push_back("19BA73EC64C3C296E1971EE5B668C591F5F206DBE5DCAA3FBAF22610767C6558");
  test_pri_key_list_.push_back("C38359CD5BD9C5FC65482FFE0E016B2E5E046F7A99E0EFDBCCDF23D2D12C7A3E");
  test_pri_key_list_.push_back("6EDB77B51291C19D82B1105A507008D10B5A0C5CCB5459129D64A3AD8D8AEEFC");
  ui->cmbTestPrivateKey->insertItems(0, test_pri_key_list_);
}

StoreExampleMainWidget::~StoreExampleMainWidget(){
  delete ui;
}

void StoreExampleMainWidget::on_cmbTestPrivateKey_currentTextChanged(const QString &arg1){
  ambr::core::PrivateKey pri_key(arg1.toStdString());
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ui->edtTestPublicKey->setText(pub_key.encode_to_hex().c_str());
}

void StoreExampleMainWidget::on_btnPriKey2PubKey_clicked(){
  ambr::core::PrivateKey key(ui->edtTx1->text().toStdString().c_str());
  ui->edtTx2->setText(ambr::core::GetPublicKeyByPrivateKey(key).encode_to_hex().c_str());
}

void StoreExampleMainWidget::on_btnPubKey2Addr_clicked(){
  ambr::core::PublicKey key(ui->edtTx1->text().toStdString().c_str());
  ui->edtTx2->setText(ambr::core::GetAddressStringByPublicKey(key).c_str());
}

void StoreExampleMainWidget::on_btnAccountBalance_clicked(){
  ambr::core::PublicKey pub_key;
  ambr::core::Amount amount;
  if(ui->rdoABPub->isChecked()){
    if(!pub_key.decode_from_hex(ui->edtABEdit->text().toStdString())){
      ui->edtABPlanEdit->setPlainText("Public key is error!");
      return;
    }
  }else{
    std::string addr = ui->edtABEdit->text().toStdString();
    if(!ambr::core::AddressIsValidate(addr)){
      ui->edtABPlanEdit->setPlainText("Address format is error!");
      return;
    }
    pub_key = ambr::core::GetPublicKeyByAddress(addr);
  }

  if(!ambr::store::GetStoreManager()->GetBalanceByPubKey(pub_key, amount)){
    ui->edtABPlanEdit->setPlainText("Account is not found!");
  }else{
    ui->edtABPlanEdit->setPlainText(QString("Account balance is:")+amount.encode_to_dec().c_str());
  }
}

void StoreExampleMainWidget::on_btnAccountList_clicked(){
  std::list<ambr::core::UnitHash> wait_for_list = ambr::store::GetStoreManager()->GetAccountListFromWaitForReceiveForDebug();
  std::list<ambr::core::UnitHash> account_list = ambr::store::GetStoreManager()->GetAccountListFromAccountForDebug();
  std::unordered_map<ambr::core::UnitHash, bool> list_map;
  //boost::unordered_map<ambr::core::UnitHash, bool> list_map;
  for(auto iter = wait_for_list.begin(); iter!= wait_for_list.end(); iter++){
    list_map[*iter] = false;
  }
  for(auto iter = account_list.begin(); iter!= account_list.end(); iter++){
    list_map[*iter] = true;
  }
  QString str;
  for(auto iter = list_map.begin(); iter != list_map.end(); iter++){
    str = str + iter->first.encode_to_hex().c_str()+":"+(iter->second?"(has account)":"(in wait for receive)")+"\n";
  }
  ui->edtALPlanEdit->setPlainText(str);
}

void StoreExampleMainWidget::on_btnUnReceived_clicked(){
  ambr::core::PublicKey pub_key;
  if(ui->rdoURPubKey->isChecked()){
    if(!pub_key.decode_from_hex(ui->edtUREdit->text().toStdString())){
      ui->edtURPlanText->setPlainText("Public key is error!");
      return;
    }
  }else{
    std::string addr = ui->edtUREdit->text().toStdString();
    if(!ambr::core::AddressIsValidate(addr)){
      ui->edtURPlanText->setPlainText("Address format is error!");
      return;
    }
    pub_key = ambr::core::GetPublicKeyByAddress(addr);
  }
  std::list<ambr::core::UnitHash> hash_list = ambr::store::GetStoreManager()->GetWaitForReceiveList(pub_key);
  QString str;
  for(auto iter = hash_list.begin(); iter != hash_list.end(); iter++){
    ambr::core::Amount amount;
    assert(ambr::store::GetStoreManager()->GetSendAmount(*iter, amount, nullptr));
    str = str+"UnitHash:"+iter->encode_to_hex().c_str()+",ammount is:"+amount.encode_to_dec().c_str()+"\n";
  }
  ui->edtURPlanText->setPlainText(str);
}

void StoreExampleMainWidget::on_btnTranslateHistory_clicked(){
  ambr::core::PublicKey pub_key;
  if(ui->rdoTHPubKey->isChecked()){
    if(!pub_key.decode_from_hex(ui->edtTHEdit->text().toStdString())){
      ui->edtTHPlanText->setPlainText("Public key is error!");
      return;
    }
  }else{
    std::string addr = ui->edtTHEdit->text().toStdString();
    if(!ambr::core::AddressIsValidate(addr)){
      ui->edtTHPlanText->setPlainText("Address format is error!");
      return;
    }
    pub_key = ambr::core::GetPublicKeyByAddress(addr);
  }
  QString str;
  std::list<std::shared_ptr<ambr::store::UnitStore> > history = ambr::store::GetStoreManager()->GetTradeHistoryByPubKey(pub_key, 100);
  for(auto iter = history.begin(); iter != history.end(); iter++){
    std::shared_ptr<ambr::store::UnitStore> store = *iter;
    if(store->type() == ambr::store::UnitStore::ST_SendUnit){
      ambr::core::Amount amount;
      if(ambr::store::GetStoreManager()->GetSendAmount(store->GetUnit()->hash(), amount, nullptr)){
        str = str+"UnitHash:"+store->GetUnit()->hash().encode_to_hex().c_str()+", send amount:"+amount.encode_to_dec().c_str()+"\n";
      }
    }else if(store->type() == ambr::store::UnitStore::ST_ReceiveUnit){
      ambr::core::Amount amount;
      auto receive_store = std::dynamic_pointer_cast<ambr::store::ReceiveUnitStore> (store);
      if(ambr::store::GetStoreManager()->GetSendAmount(receive_store->unit()->from(), amount, nullptr)){
        str = str+"UnitHash:"+store->GetUnit()->hash().encode_to_hex().c_str()+", receive amount:"+amount.encode_to_dec().c_str()+"\n";
      }
    }
  }
  ui->edtTHPlanText->setPlainText(str);
}

void StoreExampleMainWidget::on_radioButton_10_clicked(){
  ui->stackTranslate->setCurrentIndex(1);
}

void StoreExampleMainWidget::on_radioButton_9_clicked(){
  ui->stackTranslate->setCurrentIndex(0);
}

void StoreExampleMainWidget::on_btnTranslateSend_clicked(){
  ambr::core::PrivateKey pri_key = ambr::core::PrivateKey(ui->edtTSPrivate->text().toStdString());
  //ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::PublicKey dest;
  if(ui->rdoTSPubKey->isChecked()){
    if(!dest.decode_from_hex(ui->edtTSDest->text().toStdString())){
      ui->edtTSPlainEdit->setPlainText("Dest public key is error!");
      return;
    }
  }else{
    std::string addr = ui->edtTSDest->text().toStdString();
    if(!ambr::core::AddressIsValidate(addr)){
      ui->edtTSPlainEdit->setPlainText("Dest address format is error!");
      return;
    }
    dest = ambr::core::GetPublicKeyByAddress(addr);
  }
  ambr::core::Amount amount;
  amount.set_data(ui->edtTSAmount->text().toLongLong());
  std::string err;
  QString str;
  ambr::core::UnitHash hash;
  if(ambr::store::GetStoreManager()->SendToAddress(dest, amount, pri_key, &hash, &err)){
    str = str + "Send success.tx_hash:" + hash.encode_to_hex().c_str();
  }else{
    str = str + "Send faild. tx_hash:" + hash.encode_to_hex().c_str();
  }
  ui->edtTSPlainEdit->setPlainText(str);
}

void StoreExampleMainWidget::on_btnTranslateReceive_clicked(){
  ambr::core::PrivateKey pri_key = ambr::core::PrivateKey(ui->edtTRPriKey->text().toStdString());
  ambr::core::PublicKey from;
  if(ui->rdoTRPublic->isChecked()){
    if(!from.decode_from_hex(ui->edtTRFrom->text().toStdString())){
      ui->edtTRPlaintEdit->setPlainText("From public key is error!");
      return;
    }
  }else{
    std::string addr = ui->edtTRFrom->text().toStdString();
    if(!ambr::core::AddressIsValidate(addr)){
      ui->edtTRPlaintEdit->setPlainText("From address format is error!");
      return;
    }
    from = ambr::core::GetPublicKeyByAddress(addr);
  }
  ambr::core::Amount amount;
  amount.set_data(ui->edtTSAmount->text().toLongLong());
  std::string err;
  QString str;
  ambr::core::UnitHash hash;
  if(ambr::store::GetStoreManager()->ReceiveFromUnitHash(from, pri_key, &hash, &err)){
    ambr::core::Amount amount;
    assert(ambr::store::GetStoreManager()->GetSendAmount(from, amount, &err));
    str = str + "Receive " + amount.encode_to_dec().c_str() + "success.tx_hash:" + hash.encode_to_hex().c_str();
  }else{
    str = str + "Receive faild. tx_hash:" + hash.encode_to_hex().c_str();
  }
  ui->edtTRPlaintEdit->setPlainText(str);
}
