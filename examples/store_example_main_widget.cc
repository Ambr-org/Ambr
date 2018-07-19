#include "store_example_main_widget.h"
#include "ui_store_example_main_widget.h"
#include <QPainter>
#include <QTransform>
#include <QDebug>

#include <store/store_manager.h>
#include <unordered_map>
#include <store/unit_store.h>

static uint32_t height_distance = 200;
static uint32_t width_distance = 200;
static uint32_t unit_width = 100;

StoreExampleMainWidget::StoreExampleMainWidget(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::StoreExampleMainWidget),max_chain_length_for_draw_(10)
{
  ui->setupUi(this);
  ui->wgtPaint->installEventFilter(this);
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

bool StoreExampleMainWidget::eventFilter(QObject *target, QEvent *event)
{
  if(target == ui->wgtPaint && event->type() == QEvent::Paint){
    DrawChain();
  }else if(target == ui->wgtPaint && event->type() == QEvent::MouseMove){
    return OnMouseMove(event);
  }else if(target == ui->wgtPaint && event->type() == QEvent::MouseButtonPress){
    return OnMousePress(event);
  }
  return QWidget::eventFilter(target, event);
}

void StoreExampleMainWidget::DrawChain(){
  QPainter pt(ui->wgtPaint);
  DrawUnit(pt);
  DrawLines(pt);
  //DrawLine(pt, QPoint(5,5), QPoint(95,95), true);
}

void StoreExampleMainWidget::DrawUnit(QPainter& pt){
  //clear
  unit_list_.clear();
  unit_map_.clear();

  ui->wgtPaint->setFixedSize(3000,3000);

  std::shared_ptr<ambr::store::StoreManager> store_manager = ambr::store::GetStoreManager();
  std::list<ambr::core::UnitHash> unit_list = store_manager->GetAccountListFromAccountForDebug();
  uint32_t hori_idx = 0, vert_idx = 0;
  for(auto iter_account = unit_list.begin(); iter_account != unit_list.end(); iter_account++){
    //ambr::core::UnitHash account_hash = *iter_account;
    std::list<std::shared_ptr<ambr::store::UnitStore> > unit_list = store_manager->GetTradeHistoryByPubKey(*iter_account, max_chain_length_for_draw_);
    vert_idx = 0;
    for(auto iter_unit = unit_list.begin(); iter_unit != unit_list.end(); iter_unit++){
      uint32_t space_y = (max_chain_length_for_draw_ - vert_idx)*height_distance+unit_width/2;
      uint32_t space_x = (hori_idx)*width_distance+unit_width*2;
      auto item = std::make_shared<DrawItem>();
      item->space_ = QPoint(space_x, space_y);
      //item->status_ = DrawItem::DI_NORMAL;
      item->unit_store_ = *iter_unit;
      unit_list_[*iter_account].push_back(item);
      //DrawItem* xxx;
      unit_map_[item->unit_store_->GetUnit()->hash()] = item;
      pt.save();
      if(item->unit_store_->GetUnit()->hash() == active_unit_){
        pt.setPen(qRgb(125,0,0));
      }
      if(item->unit_store_->GetUnit()->hash() == selected_unit_){
        pt.setPen(qRgb(255,0,0));
      }
      pt.drawEllipse(item->space_, unit_width/2, unit_width/2);
      QString str_hash =(*iter_unit)->GetUnit()->hash().encode_to_hex().c_str();
      str_hash = str_hash.left(4)+"...."+str_hash.right(4);
      pt.drawText(QPoint(space_x-unit_width/2+10, space_y), str_hash);
      //std::cout<<"draw:"<<item->space_.x()<<","<<item->space_.y()<<std::endl;
      pt.restore();
      vert_idx++;
    }
    //draw account
    QPen old_pen = pt.pen();
    pt.setPen(qRgb(175,175,175));
    QString str_hash = iter_account->encode_to_hex().c_str();
    str_hash = str_hash.left(4)+"...."+str_hash.right(4);
    uint32_t space_y = unit_width/2;
    uint32_t space_x = (hori_idx)*width_distance+unit_width*2;
    pt.drawEllipse(QPoint(space_x, space_y), unit_width/2, unit_width/2);
    pt.setPen(old_pen);
    pt.drawText(QPoint(space_x-unit_width/2+10, space_y), str_hash);
    hori_idx++;
  }

}

void StoreExampleMainWidget::DrawLines(QPainter &pt){
  //std::unordered_map<ambr::core::UnitHash, std::shared_ptr<DrawItem> unit_map_;
  for(std::pair<ambr::core::UnitHash, std::shared_ptr<DrawItem>> item: unit_map_){
    QPoint pt_start = item.second->space_;
    std::shared_ptr<ambr::core::Unit> unit = item.second->unit_store_->GetUnit();
    if(!unit){
      continue;
    }
    ambr::core::UnitHash prv_hash = unit->prev_unit();
    if(prv_hash.is_zero()){
      QPoint pt_end;
      pt_end.setX(pt_start.x());
      pt_end.setY(unit_width/2);
      DrawLine(pt, pt_start, pt_end, false);
    }else{
      auto iter_prv = unit_map_.find(prv_hash);
      if(iter_prv == unit_map_.end()){
        QPoint pt_end;
        pt_end.setX(pt_start.x());
        pt_end.setY(unit_width/2);
        QPen pen_old = pt.pen();
        pt.setPen(Qt::DotLine);
        DrawLine(pt, pt_start, pt_end, false);
        pt.setPen(pen_old);
      }else{
        QPoint pt_end = iter_prv->second->space_;
        DrawLine(pt, pt_start, pt_end, true);
      }
    }
    if(std::shared_ptr<ambr::core::SendUnit> send_unit =
       std::dynamic_pointer_cast<ambr::core::SendUnit>(item.second->unit_store_->GetUnit())){

    }else if(std::shared_ptr<ambr::core::ReceiveUnit> receive_unit =
        std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(item.second->unit_store_->GetUnit())){
      auto iter = unit_map_.find(receive_unit->from());
      if(iter != unit_map_.end()){
        QPoint pt_end = iter->second->space_;
        DrawLine(pt, pt_start, pt_end, true);
      }
    }
  }

}

void StoreExampleMainWidget::DrawLine(QPainter &pt, const QPoint &from, const QPoint &to, bool b_arrow){
  double arrow_line = 15.0;
  double slopy = atan2((to.y() - from.y()), (to.x() - from.x()));
  double cosy = cos(slopy);
  double siny = sin(slopy);
  QPoint point1 = QPoint(to.x() + int(-arrow_line*cosy - (arrow_line / 2.0*siny)), to.y() + int(-arrow_line*siny + (arrow_line / 2.0*cosy)));
  QPoint point2 = QPoint(to.x() + int(-arrow_line*cosy + (arrow_line / 2.0*siny)), to.y() - int(arrow_line / 2.0*cosy + arrow_line*siny));
  pt.drawLine(point1.x(), point1.y(), to.x(), to.y());
  pt.drawLine(point2.x(), point2.y(), to.x(), to.y());
  pt.drawLine(from, to);
}

bool StoreExampleMainWidget::OnMouseMove(QEvent *event){
  QMouseEvent* mouse_event = dynamic_cast<QMouseEvent*>(event);
  if(mouse_event){
    ambr::core::UnitHash old_active = active_unit_;
    active_unit_.clear();
    QPoint pos = mouse_event->pos();
    for(std::pair<ambr::core::UnitHash, std::shared_ptr<DrawItem>> item: unit_map_){
      if(pow(item.second->space_.x() - pos.x(), 2) + pow(item.second->space_.y() - pos.y(), 2) < pow(unit_width/2, 2)){
        active_unit_ = item.first;
        break;
      }
      std::cout<<sqrt(item.second->space_.x() - pos.x()) + sqrt(item.second->space_.y() - pos.y())<<":<<"<<sqrt(unit_width/2)<<std::endl;
    }
    if(active_unit_ != old_active){
      ui->wgtPaint->update();
      return true;
    }
  }
  return false;
}

bool StoreExampleMainWidget::OnMousePress(QEvent *event){
  if(event->type() == QEvent::MouseButtonPress){
    ambr::core::UnitHash old_selected = selected_unit_;
    selected_unit_ = active_unit_;
    if(old_selected != selected_unit_){
      ui->wgtPaint->update();
      std::shared_ptr<ambr::store::UnitStore> unit = ambr::store::GetStoreManager()->GetUnit(selected_unit_);
      if(unit){
        ui->edtShowJson->setPlainText(unit->SerializeJson().c_str());
      }else{
        ui->edtShowJson->setPlainText("");
      }
      return true;
    }
  }
  return false;
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
void StoreExampleMainWidget::on_btnUnit_clicked(){
    ambr::core::UnitHash unit_hash(ui->edtUnit->text().toStdString());
    std::shared_ptr<ambr::store::UnitStore> unit = ambr::store::GetStoreManager()->GetUnit(unit_hash);
    if(!unit){
      ui->edtUnitPlainEdit->setPlainText("Couldn't find unit!");
    }else{
      ui->edtUnitPlainEdit->setPlainText(unit->GetUnit()->SerializeJson().c_str());
    }
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

void StoreExampleMainWidget::on_btnPTLength_clicked(){
  max_chain_length_for_draw_ = ui->edtPTLength->text().toInt();
  if(max_chain_length_for_draw_ < 1)max_chain_length_for_draw_ = 1;
  ui->wgtPaint->repaint();
}

void StoreExampleMainWidget::on_btnPTRepaint_clicked(){
  ui->wgtPaint->repaint();
}


