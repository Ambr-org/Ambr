#include "store_example_main_widget.h"
#include "ui_store_example_main_widget.h"
#include <QPainter>
#include <QTransform>
#include <QDebug>
#include <QTime>
#include <glog/logging.h>
#include <store/store_manager.h>
#include <unordered_map>
#include <store/unit_store.h>
#include "netmessagemaker.h"
#include <boost/thread.hpp>

static uint32_t height_distance = 100;
static uint32_t width_distance = 100;
static uint32_t unit_width = 50;

StoreExampleMainWidget::StoreExampleMainWidget(std::shared_ptr<ambr::store::StoreManager> store_manager, std::shared_ptr<ambr::syn::SynManager> syn_manager, QWidget *parent) :
  QWidget(parent),
  ui(new Ui::StoreExampleMainWidget),max_chain_length_for_draw_(10),
  p_syn_manager(syn_manager),
  store_manager_(store_manager),
  tps_count_(0)
{
  assert(store_manager_);
  ui->setupUi(this);
  ui->wgtPaint->installEventFilter(this);
  //tab init
  ui->tabMain->setCurrentIndex(2);
  ui->tabMain->setTabEnabled(0, false);
  ui->tabMain->setTabEnabled(1, false);
  ui->tabMain->setTabEnabled(3, false);
  ui->tabDebugUp->setCurrentIndex(0);
  ui->tabDebugDown->setCurrentIndex(0);
  ui->stackTranslate->setCurrentIndex(0);
  root_pri_key_ = "25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC";
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

  connect(this, SIGNAL(sgAccept(QString)), this, SLOT(onDealAccept(QString)));
  connect(this, SIGNAL(sgConnect(QString)), this, SLOT(onDealConnect(QString)));
  connect(this, SIGNAL(sgDisconnected(QString)), this, SLOT(onDealDisconnected(QString)));

  store_manager_->AddCallBackReceiveNewSendUnit(std::bind(&StoreExampleMainWidget::OnGetNewUnit, this));
  store_manager_->AddCallBackReceiveNewReceiveUnit(std::bind(&StoreExampleMainWidget::OnGetNewUnit, this));
  store_manager_->AddCallBackReceiveNewValidatorUnit(std::bind(&StoreExampleMainWidget::OnGetNewUnit, this));
  store_manager_->AddCallBackReceiveNewJoinValidatorSetUnit(std::bind(&StoreExampleMainWidget::OnGetNewUnit, this));
  store_manager_->AddCallBackReceiveNewLeaveValidatorSetUnit(std::bind(&StoreExampleMainWidget::OnGetNewUnit, this));
  for(int i = 0; i < 32; i++){
    validator_auto_.push_back(std::make_shared<ambr::utils::ValidatorAuto>(store_manager));
  }

}

StoreExampleMainWidget::~StoreExampleMainWidget(){
  for(std::shared_ptr<ambr::utils::ValidatorAuto> auto_item:validator_auto_){
    auto_item->StopAutoRun();
  }
  //std::unordered_map<ambr::core::PrivateKey, std::pair<bool, std::shared_ptr<std::thread>>> auto_publish_trans_thread_map_;
  for(auto item:auto_publish_trans_thread_map_){
    auto_publish_trans_thread_map_[item.first].first = false;
    //item.second.first = false;
    item.second.second->join();
  }
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
  QFont font;
  font.setPixelSize(unit_width/5);
  pt.setFont(font);
  DrawUnit(pt);
  DrawLines(pt);
}

void StoreExampleMainWidget::DrawUnit(QPainter& pt){
  //clear
  unit_list_.clear();
  unit_map_.clear();
  ui->wgtPaint->setFixedHeight((max_chain_length_for_draw_)*height_distance+unit_width+10);
  ui->wgtPaint->setFixedWidth((store_manager_->GetAccountListFromAccountForDebug().size()+1)*width_distance+unit_width);

  std::shared_ptr<ambr::store::StoreManager> store_manager = store_manager_;
  std::list<ambr::core::UnitHash> unit_list = store_manager->GetAccountListFromAccountForDebug();
  uint32_t hori_idx = 0, vert_idx = 0;
  for(auto iter_account = unit_list.begin(); iter_account != unit_list.end(); iter_account++){
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
      pt.drawText(QPoint(space_x-unit_width/2, space_y), str_hash);
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
    pt.drawText(QPoint(space_x-unit_width/2, space_y), str_hash);
    hori_idx++;
  }
  //draw validator unit
  std::list<std::shared_ptr<ambr::core::ValidatorUnit> > validator_unit_list = store_manager->GetValidateHistory(max_chain_length_for_draw_);
  vert_idx = 0;
  QPen old_pen_tmp = pt.pen();
  QPen validator_pen(old_pen_tmp);
  validator_pen.setColor(qRgb(237,137,65));
  pt.setPen(validator_pen);
  for(auto iter_unit = validator_unit_list.begin(); iter_unit != validator_unit_list.end(); iter_unit++){
    uint32_t space_y = (max_chain_length_for_draw_ - vert_idx)*height_distance+unit_width/2;
    uint32_t space_x = (hori_idx)*width_distance+unit_width*2;
    auto item = std::make_shared<DrawItem>();
    item->space_ = QPoint(space_x, space_y);
    //item->status_ = DrawItem::DI_NORMAL;
    item->validator_unit_store_ = *iter_unit;
    unit_list_[ambr::core::UnitHash()].push_back(item);
    //DrawItem* xxx;
    unit_map_[item->validator_unit_store_->hash()] = item;
    pt.save();
    if(item->validator_unit_store_->hash() == active_unit_){
      pt.setPen(qRgb(125,0,0));
    }
    if(item->validator_unit_store_->hash() == selected_unit_){
      pt.setPen(qRgb(255,0,0));
    }
    pt.drawEllipse(item->space_, unit_width/2, unit_width/2);
    QString str_hash =(*iter_unit)->hash().encode_to_hex().c_str();
    str_hash = str_hash.left(4)+"...."+str_hash.right(4);
    pt.drawText(QPoint(space_x-unit_width/2+10, space_y), str_hash);
    pt.restore();
    vert_idx++;
  }
  pt.setPen(old_pen_tmp);
  //draw account
  QPen old_pen = pt.pen();
  pt.setPen(qRgb(175,175,175));
  QString str_hash;// = iter_account->encode_to_hex().c_str();
  str_hash = str_hash.left(4)+"...."+str_hash.right(4);
  uint32_t space_y = unit_width/2;
  uint32_t space_x = (hori_idx)*width_distance+unit_width*2;
  pt.drawEllipse(QPoint(space_x, space_y), unit_width/2, unit_width/2);
  pt.setPen(old_pen);
  pt.drawText(QPoint(space_x-unit_width/2, space_y), str_hash);
  hori_idx++;
}

void StoreExampleMainWidget::DrawLines(QPainter &pt){
  //std::unordered_map<ambr::core::UnitHash, std::shared_ptr<DrawItem> unit_map_;
  for(std::pair<ambr::core::UnitHash, std::shared_ptr<DrawItem>> item: unit_map_){
    QPoint pt_start = item.second->space_;
    if(item.second->unit_store_){
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
    }else if(item.second->validator_unit_store_){
      QPen pen_old = pt.pen();
      QPen pen_new(pen_old);
      pen_new.setColor(qRgb(237,167,65));
      pt.setPen(pen_new);
      std::shared_ptr<ambr::core::ValidatorUnit> unit = item.second->validator_unit_store_;
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
          //QPen pen_old = pt.pen();
          pen_new.setStyle(Qt::DotLine);
          pt.setPen(pen_new);
          DrawLine(pt, pt_start, pt_end, false);
          pen_new.setStyle(Qt::SolidLine);
          pt.setPen(pen_new);
        }else{
          QPoint pt_end = iter_prv->second->space_;
          DrawLine(pt, pt_start, pt_end, true);
        }
      }
      std::vector<ambr::core::UnitHash> check_list = unit->check_list();
      for(auto hash_check:check_list){
        auto iter = unit_map_.find(hash_check);
        if(iter != unit_map_.end()){
          QPoint pt_end = iter->second->space_;
          DrawLine(pt, pt_start, pt_end, true);
        }
      }
      pt.setPen(pen_old);
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
      //std::cout<<sqrt(item.second->space_.x() - pos.x()) + sqrt(item.second->space_.y() - pos.y())<<":<<"<<sqrt(unit_width/2)<<std::endl;
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
      std::shared_ptr<ambr::store::UnitStore> unit = store_manager_->GetUnit(selected_unit_);
      if(unit){
        ui->edtShowJson->setPlainText(unit->SerializeJson().c_str());
      }else{
        std::shared_ptr<ambr::store::ValidatorUnitStore> unit_validator_store = store_manager_->GetValidateUnit(selected_unit_);
        std::shared_ptr<ambr::core::ValidatorUnit> unit_validator;
        if(unit_validator_store && (unit_validator = unit_validator_store->unit())){
          ui->edtShowJson->setPlainText(unit_validator->SerializeJson().c_str());
        }
      }
      return true;
    }
  }
  return false;
}

void StoreExampleMainWidget::OnAcceptNode(CNode* p_node){
  emit sgAccept(p_node->GetAddrName().c_str());
}

void StoreExampleMainWidget::OnConnectNode(CNode* p_node){
  emit sgConnect(p_node->GetAddrName().c_str());
}

void StoreExampleMainWidget::OnDisconnectedNode(CNode* p_node){
  emit sgDisconnected(p_node->GetAddrName().c_str());
}

void StoreExampleMainWidget::CheckValidatorUnit(){
  std::shared_ptr<ambr::core::ValidatorUnit> unit = std::make_shared<ambr::core::ValidatorUnit>();
  unit->set_version(0x00000001);
  unit->set_type(ambr::core::UnitType::Validator);
  unit->set_public_key("0x1234567890123456789012345678901234567890123456789012345678901234");
  unit->set_prev_unit("0x1234567890123456789012345678901234567890123456789012345678901235");
  unit->set_balance((boost::multiprecision::uint128_t)123456);

  std::vector<ambr::core::UnitHash> hash_list;
  hash_list.push_back("0x1234567890123456789012345678901234567890123456789012345678901231");
  hash_list.push_back("0x1234567890123456789012345678901234567890123456789012345678901232");
  hash_list.push_back("0x1234567890123456789012345678901234567890123456789012345678901233");
  hash_list.push_back("0x1234567890123456789012345678901234567890123456789012345678901234");
  unit->set_check_list(hash_list);
  hash_list.push_back("0x1234567890123456789012345678901234567890123456789012345678901235");
  unit->set_vote_hash_list(hash_list);
  unit->set_time_stamp_with_now();
  unit->CalcHashAndFill();
  unit->SignatureAndFill("0x1234567890123456789012345678901234567890123456789012345678901231");
  std::string json_str = unit->SerializeJson();

  LOG(INFO)<<json_str;
  std::shared_ptr<ambr::core::ValidatorUnit> unit_2 = std::make_shared<ambr::core::ValidatorUnit>();
  unit_2->DeSerializeJson(json_str);
  LOG(INFO)<<unit_2->SerializeJson();

  std::vector<uint8_t> buf = unit->SerializeByte();
  std::shared_ptr<ambr::core::ValidatorUnit> unit_3 = std::make_shared<ambr::core::ValidatorUnit>();
  unit_3->DeSerializeByte(buf);
  LOG(INFO)<<unit_3->SerializeJson();
}

void StoreExampleMainWidget::CreateDebugInitChain(){
  ambr::core::UnitHash tx_hash[10];
  std::shared_ptr<ambr::core::Unit> unit_sended;

  //send
  store_manager_->SendToAddress(ambr::core::PrivateKey(
    ambr::core::GetPublicKeyByPrivateKey(test_pri_key_list_[0].toStdString())),
    "100000000000",
    ambr::core::PrivateKey(root_pri_key_.toStdString()),
    &tx_hash[0],
    unit_sended,
    nullptr
  );
  store_manager_->SendToAddress(ambr::core::PrivateKey(
    ambr::core::GetPublicKeyByPrivateKey(test_pri_key_list_[1].toStdString())),
    "100000000000",
    ambr::core::PrivateKey(root_pri_key_.toStdString()),
    &tx_hash[1],
    unit_sended,
    nullptr
  );
  store_manager_->SendToAddress(ambr::core::PrivateKey(
    ambr::core::GetPublicKeyByPrivateKey(test_pri_key_list_[2].toStdString())),
    "100000000000",
    ambr::core::PrivateKey(root_pri_key_.toStdString()),
    &tx_hash[2],
    unit_sended,
    nullptr
  );
  store_manager_->SendToAddress(ambr::core::PrivateKey(
    ambr::core::GetPublicKeyByPrivateKey(test_pri_key_list_[3].toStdString())),
    "100000000000",
    ambr::core::PrivateKey(root_pri_key_.toStdString()),
    &tx_hash[3],
    unit_sended,
    nullptr
  );
  store_manager_->SendToAddress(ambr::core::PrivateKey(
    ambr::core::GetPublicKeyByPrivateKey(test_pri_key_list_[4].toStdString())),
    "100000000000",
    ambr::core::PrivateKey(root_pri_key_.toStdString()),
    &tx_hash[4],
    unit_sended,
    nullptr
  );
  //receive
  store_manager_->ReceiveFromUnitHash(
    tx_hash[0],
    ambr::core::PrivateKey(test_pri_key_list_[0].toStdString()),
    &tx_hash[9],
    unit_sended,
    nullptr);
  store_manager_->ReceiveFromUnitHash(
    tx_hash[1],
    ambr::core::PrivateKey(test_pri_key_list_[1].toStdString()),
    &tx_hash[9],
    unit_sended,
    nullptr);
  store_manager_->ReceiveFromUnitHash(
    tx_hash[2],
    ambr::core::PrivateKey(test_pri_key_list_[2].toStdString()),
    &tx_hash[2],
    unit_sended,
    nullptr);
  store_manager_->ReceiveFromUnitHash(
    tx_hash[3],
    ambr::core::PrivateKey(test_pri_key_list_[3].toStdString()),
    &tx_hash[9],
    unit_sended,
    nullptr);
  store_manager_->ReceiveFromUnitHash(
    tx_hash[4],
    ambr::core::PrivateKey(test_pri_key_list_[4].toStdString()),
    &tx_hash[9],
    unit_sended,
    nullptr);
  store_manager_->JoinValidatorSet(
    ambr::core::PrivateKey(test_pri_key_list_[0].toStdString()),
    "80000000000",&tx_hash[9],unit_sended,nullptr);
  store_manager_->JoinValidatorSet(
    ambr::core::PrivateKey(test_pri_key_list_[1].toStdString()),
    "80000000000",&tx_hash[9],unit_sended,nullptr);
  store_manager_->JoinValidatorSet(
    ambr::core::PrivateKey(test_pri_key_list_[2].toStdString()),
    "80000000000",&tx_hash[9],unit_sended,nullptr);
  store_manager_->JoinValidatorSet(
    ambr::core::PrivateKey(test_pri_key_list_[3].toStdString()),
    "80000000000",&tx_hash[9],unit_sended,nullptr);
  store_manager_->JoinValidatorSet(
    ambr::core::PrivateKey(test_pri_key_list_[4].toStdString()),
    "80000000000",&tx_hash[9],unit_sended,nullptr);

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

  if(!store_manager_->GetBalanceByPubKey(pub_key, amount)){
    ui->edtABPlanEdit->setPlainText("Account is not found!");
  }else{
    ui->edtABPlanEdit->setPlainText(QString("Account balance is:")+amount.encode_to_dec().c_str());
  }
}

void StoreExampleMainWidget::on_btnAccountList_clicked(){
  std::list<ambr::core::UnitHash> wait_for_list = store_manager_->GetAccountListFromWaitForReceiveForDebug();
  std::list<ambr::core::UnitHash> account_list = store_manager_->GetAccountListFromAccountForDebug();
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
  std::list<ambr::core::UnitHash> hash_list = store_manager_->GetWaitForReceiveList(pub_key);
  QString str;
  for(auto iter = hash_list.begin(); iter != hash_list.end(); iter++){
    ambr::core::Amount amount;
    assert(store_manager_->GetSendAmount(*iter, amount, nullptr));
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
  std::list<std::shared_ptr<ambr::store::UnitStore> > history = store_manager_->GetTradeHistoryByPubKey(pub_key, 100);
  for(auto iter = history.begin(); iter != history.end(); iter++){
    std::shared_ptr<ambr::store::UnitStore> store = *iter;
    if(store->type() == ambr::store::UnitStore::ST_SendUnit){
      ambr::core::Amount amount;
      if(store_manager_->GetSendAmount(store->GetUnit()->hash(), amount, nullptr)){
        str = str+"UnitHash:"+store->GetUnit()->hash().encode_to_hex().c_str()+", send amount:"+amount.encode_to_dec().c_str()+"\n";
      }
    }else if(store->type() == ambr::store::UnitStore::ST_ReceiveUnit){
      ambr::core::Amount amount;
      auto receive_store = std::dynamic_pointer_cast<ambr::store::ReceiveUnitStore> (store);
      if(store_manager_->GetSendAmount(receive_store->unit()->from(), amount, nullptr)){
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

void StoreExampleMainWidget::on_radioButton_11_clicked(){
  ui->stackTranslate->setCurrentIndex(2);
}

void StoreExampleMainWidget::on_radioButton_12_clicked(){
  ui->stackTranslate->setCurrentIndex(3);
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
  ambr::core::SendUnit::DataType data_type;
  if(ui->rdoTSNormal->isChecked()){
    data_type = ambr::core::SendUnit::Normal;
  }else if(ui->rdoTSCreateContract->isChecked()){
    data_type = ambr::core::SendUnit::CreateContract;
  }else if(ui->rdoTSRunContract->isChecked()){
    data_type = ambr::core::SendUnit::RunContract;
  }
  QString addition = ui->edtTSAddtion->toPlainText();

  std::string err;
  QString str;
  ambr::core::UnitHash hash;
  std::shared_ptr<ambr::core::Unit> unit_out;
  if(store_manager_->SendToAddressWithContract(dest, amount, pri_key, data_type, addition.toStdString(), &hash, unit_out, &err)){
    {//boardcast to net
      std::vector<uint8_t> buf = unit_out->SerializeByte();
      std::string str_data;
      str_data.assign(buf.begin(), buf.end());
    }
    str = str + "Send success.tx_hash:" + hash.encode_to_hex().c_str();
  }else{
    str = str + "Send faild. err:" + err.c_str();
  }
  ui->edtTSPlainEdit->setPlainText(str);
}
void StoreExampleMainWidget::on_btnUnit_clicked(){
    ambr::core::UnitHash unit_hash(ui->edtUnit->text().toStdString());
    std::shared_ptr<ambr::store::UnitStore> unit = store_manager_->GetUnit(unit_hash);
    if(!unit){
      ui->edtUnitPlainEdit->setPlainText("Couldn't find unit!");
    }else{
      ui->edtUnitPlainEdit->setPlainText(unit->SerializeJson().c_str());
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
  if(ui->rdoTRFromSend->isChecked()){
    ambr::core::Amount amount;
    amount.set_data(ui->edtTSAmount->text().toLongLong());
    std::string err;
    QString str;
    ambr::core::UnitHash hash;
    std::shared_ptr<ambr::core::Unit> unit_out;
    if(store_manager_->ReceiveFromUnitHash(from, pri_key, &hash, unit_out, &err)){
      ambr::core::Amount amount;
      assert(store_manager_->GetSendAmount(from, amount, &err));
      str = str + "Receive " + amount.encode_to_dec().c_str() + "success.tx_hash:" + hash.encode_to_hex().c_str();
    }else{
      str = str + "Receive faild. tx_hash:" + err.c_str();
    }
    ui->edtTRPlaintEdit->setPlainText(str);
  }else{
    ambr::core::Amount amount;
    amount.set_data(ui->edtTSAmount->text().toLongLong());
    std::string err;
    QString str;
    ambr::core::UnitHash hash;
    std::shared_ptr<ambr::core::Unit> unit_out;
    if(store_manager_->ReceiveFromValidator(pri_key, &hash, unit_out, &err)){
      str = str + "Receive success. tx_hash:" + hash.encode_to_hex().c_str();
    }else{
      str = str + "Receive faild. tx_hash:" + err.c_str();
    }
    ui->edtTRPlaintEdit->setPlainText(str);
  }
}

void StoreExampleMainWidget::on_btnPTLength_clicked(){
  max_chain_length_for_draw_ = ui->edtPTLength->text().toInt();
  if(max_chain_length_for_draw_ < 1)max_chain_length_for_draw_ = 1;
  ui->wgtPaint->repaint();
}

void StoreExampleMainWidget::on_btnPTRepaint_clicked(){
  ui->wgtPaint->repaint();
}



void StoreExampleMainWidget::on_btnInitDataBase_clicked(){
  std::string command = "rm -fr ";
  command += ui->edtDatabasePath->text().toStdString();
  system(command.c_str());
  store_manager_->Init(ui->edtDatabasePath->text().toStdString());
  google::SetLogDestination(google::GLOG_INFO, (ui->edtDatabasePath->text().toStdString()+"/log.log").c_str());
  ui->tabMain->setTabEnabled(0, true);
  ui->tabMain->setTabEnabled(1, true);
  ui->tabMain->setTabEnabled(3, true);
  ui->btnInitDataBase->setEnabled(false);
  rpc_server_.StartRpcServer(store_manager_, 10112);
  //start timmer
  chain_draw_timer.start(40);
  connect(&chain_draw_timer, SIGNAL(timeout()), this, SLOT(OnDrawTimerOut()));
  tps_timer_.start(1000);
  connect(&tps_timer_, SIGNAL(timeout()), this, SLOT(OnTpsTimer()));
  net_state_timer_.start(1000);
  connect(&net_state_timer_, SIGNAL(timeout()), this, SLOT(OnNetStateTimer()));
}

void StoreExampleMainWidget::on_btnFlushValidatorSet_clicked(){
  while(ui->tbValidatorSet->rowCount()){
    ui->tbValidatorSet->removeRow(0);
  }
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set =
      store_manager_->GetValidatorSet();
  assert(validator_set);
  for(const ambr::store::ValidatorItem& item: validator_set->validator_list()){
    ui->tbValidatorSet->insertRow(0);
    ui->tbValidatorSet->setItem(0,0, new QTableWidgetItem(item.validator_public_key_.encode_to_hex().c_str()));
    ui->tbValidatorSet->setItem(0,1,new QTableWidgetItem(item.balance_.encode_to_dec().c_str()));
    ui->tbValidatorSet->setItem(0,2, new QTableWidgetItem(QString::number(item.enter_nonce_)));
    ui->tbValidatorSet->setItem(0,3, new QTableWidgetItem(QString::number(item.leave_nonce_)));
  }
}

void StoreExampleMainWidget::on_btnAccountNew_clicked(){
  while(ui->tbAccountNew->rowCount()){
    ui->tbAccountNew->removeRow(0);
  }
  std::unordered_map<ambr::core::PublicKey, ambr::core::UnitHash> _map =
      store_manager_->GetNewUnitMap();
  for(const std::pair<ambr::core::PublicKey, ambr::core::UnitHash> item: _map){
    ui->tbAccountNew->insertRow(0);
    ui->tbAccountNew->setItem(0,0, new QTableWidgetItem(item.first.encode_to_hex().c_str()));
    ui->tbAccountNew->setItem(0,1, new QTableWidgetItem(item.second.encode_to_hex().c_str()));
  }
}

void StoreExampleMainWidget::on_btnAddSV_clicked(){
  ambr::core::PrivateKey pri_key = ui->edtSVPriKey->text().toStdString();
  ambr::core::UnitHash tx_hash;
  std::shared_ptr<ambr::core::ValidatorUnit> unit;

  std::string str_err;
  if(store_manager_->PublishValidator(pri_key, &tx_hash, unit, &str_err)){
    std::vector<uint8_t>&& buf = unit->SerializeByte();
    std::string str_data;
    str_data.assign(buf.begin(), buf.end());
    ui->edtSVLOG->setPlainText(("Success:"+unit->SerializeJson()).c_str());
  }else{
    ui->edtSVLOG->setPlainText(("Faild:"+str_err).c_str());
  }

}

void StoreExampleMainWidget::on_btnVote_clicked(){
  ambr::core::PrivateKey pri_key;
  pri_key = ui->edtVotePri->text().toStdString();
  bool accept = ui->cbAccept->isChecked();
  std::string str_err;
  std::shared_ptr<ambr::core::VoteUnit> unit;
  if(!store_manager_->PublishVote(pri_key, accept, unit, &str_err)){
    ui->edtVoteLOG->setPlainText(("Vote faild:"+str_err).c_str());
  }else{
    ui->edtVoteLOG->setPlainText(("Vote success:"+unit->SerializeJson()).c_str());
  }
}
void StoreExampleMainWidget::on_btnFlushVote_clicked(){
  while(ui->tbVote->rowCount()){
    ui->tbVote->removeRow(0);
  }
  std::list<std::shared_ptr<ambr::core::VoteUnit>> vote_list = store_manager_->GetVoteList();
  ambr::core::Amount all_balance, accept_balance;
  for(std::shared_ptr<ambr::core::VoteUnit> unit: vote_list){
    ui->tbVote->insertRow(0);
    ui->tbVote->setItem(0,0, new QTableWidgetItem(unit->validator_unit_hash().encode_to_hex().c_str()));
    ui->tbVote->setItem(0,1, new QTableWidgetItem(unit->balance().encode_to_dec().c_str()));
    ui->tbVote->setItem(0,2, new QTableWidgetItem(unit->accept()?"true":"false"));
    if(unit->accept()){
      accept_balance += unit->balance();
    }
  }
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set_list = store_manager_->GetValidatorSet();
  if(!validator_set_list){
    return;
  }
  std::shared_ptr<ambr::store::ValidatorUnitStore> validator_unit_store = store_manager_->GetLastestValidateUnit();
  if(!validator_unit_store){
    return;
  }
  std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = validator_unit_store->unit();
  if(!validator_unit){
    return;
  }
  for(ambr::store::ValidatorItem validator_item: validator_set_list->validator_list()){
    if(validator_unit->nonce() >= validator_item.enter_nonce_ ||
    (validator_unit->nonce() <= validator_item.leave_nonce_ || validator_item.leave_nonce_ != 0)){
      all_balance = all_balance+validator_item.balance_;
    }
  }
  QString str;
  str += "All Cash deposit is ";
  str += all_balance.encode_to_dec().c_str();
  str += QString(". accept percent is ")+(accept_balance*100/all_balance).encode_to_dec().c_str()+"%";
  ui->lblVote->setPlainText(str);
}

void StoreExampleMainWidget::on_btnMSVStart_1_clicked(){
  validator_auto_[0]->StartAutoRun(ui->edtMVSPriv_1->text().toStdString());
  ui->btnMSVStart_1->setEnabled(false);
  ui->btnMSVStop_1->setEnabled(true);
}

void StoreExampleMainWidget::on_btnMSVStop_1_clicked(){
  validator_auto_[0]->StopAutoRun();
  ui->btnMSVStart_1->setEnabled(true);
  ui->btnMSVStop_1->setEnabled(false);
}

void StoreExampleMainWidget::on_btnMSVStart_2_clicked(){
  validator_auto_[1]->StartAutoRun(ui->edtMVSPriv_2->text().toStdString());
  ui->btnMSVStart_2->setEnabled(false);
  ui->btnMSVStop_2->setEnabled(true);
}

void StoreExampleMainWidget::on_btnMSVStop_2_clicked(){
  validator_auto_[1]->StopAutoRun();
  ui->btnMSVStart_2->setEnabled(true);
  ui->btnMSVStop_2->setEnabled(false);
}

void StoreExampleMainWidget::on_btnMSVStart_3_clicked(){
  validator_auto_[2]->StartAutoRun(ui->edtMVSPriv_3->text().toStdString());
  ui->btnMSVStart_3->setEnabled(false);
  ui->btnMSVStop_3->setEnabled(true);
}

void StoreExampleMainWidget::on_btnMSVStop_3_clicked(){
  validator_auto_[2]->StopAutoRun();
  ui->btnMSVStart_3->setEnabled(true);
  ui->btnMSVStop_3->setEnabled(false);
}

void StoreExampleMainWidget::on_btnMSVStart_4_clicked(){
  validator_auto_[3]->StartAutoRun(ui->edtMVSPriv_4->text().toStdString());
  ui->btnMSVStart_4->setEnabled(false);
  ui->btnMSVStop_4->setEnabled(true);
}

void StoreExampleMainWidget::on_btnMSVStop_4_clicked(){
  validator_auto_[3]->StopAutoRun();
  ui->btnMSVStart_4->setEnabled(true);
  ui->btnMSVStop_4->setEnabled(false);
}

void StoreExampleMainWidget::on_btnMSVStart_5_clicked(){
  validator_auto_[4]->StartAutoRun(ui->edtMVSPriv_5->text().toStdString());
  ui->btnMSVStart_5->setEnabled(false);
  ui->btnMSVStop_5->setEnabled(true);
}

void StoreExampleMainWidget::on_btnMSVStop_5_clicked(){
  validator_auto_[4]->StopAutoRun();
  ui->btnMSVStart_5->setEnabled(true);
  ui->btnMSVStop_5->setEnabled(false);
}

void StoreExampleMainWidget::on_btnMSVStart_6_clicked(){
  validator_auto_[5]->StartAutoRun(ui->edtMVSPriv_6->text().toStdString());
  ui->btnMSVStart_6->setEnabled(false);
  ui->btnMSVStop_6->setEnabled(true);
}

void StoreExampleMainWidget::on_btnMSVStop_6_clicked(){
  validator_auto_[5]->StopAutoRun();
  ui->btnMSVStart_6->setEnabled(true);
  ui->btnMSVStop_6->setEnabled(false);
}

#define BTN_START_TRANS_FUNC(idx) \
void StoreExampleMainWidget::on_btnMSVStartTrans_##idx##_clicked(){\
  ui->btnMSVStartTrans_##idx->setEnabled(false);\
  ui->btnMSVStopTrans_##idx->setEnabled(true);\
  ambr::core::PrivateKey pri_key(ui->edtMVSPriv_##idx->text().toStdString());\
  StartPublishTrans(pri_key);\
}
BTN_START_TRANS_FUNC(1)
BTN_START_TRANS_FUNC(2)
BTN_START_TRANS_FUNC(3)
BTN_START_TRANS_FUNC(4)
BTN_START_TRANS_FUNC(5)
BTN_START_TRANS_FUNC(6)

#define BTN_STOP_TRANS_FUNC(idx) \
void StoreExampleMainWidget::on_btnMSVStopTrans_##idx##_clicked(){\
  ui->btnMSVStartTrans_##idx->setEnabled(true);\
  ui->btnMSVStopTrans_##idx->setEnabled(false);\
  ambr::core::PrivateKey pri_key(ui->edtMVSPriv_##idx->text().toStdString());\
  StopPublishTrans(pri_key);\
}
BTN_STOP_TRANS_FUNC(1)
BTN_STOP_TRANS_FUNC(2)
BTN_STOP_TRANS_FUNC(3)
BTN_STOP_TRANS_FUNC(4)
BTN_STOP_TRANS_FUNC(5)
BTN_STOP_TRANS_FUNC(6)

void StoreExampleMainWidget::onDealAccept(QString addr){
    ui->tbP2PConnectionIn->insertRow(0);
    QStringList list_addr = addr.split(':');
    ui->tbP2PConnectionIn->setItem(0, 0, new QTableWidgetItem(list_addr.at(0)));
    ui->tbP2PConnectionIn->setItem(0, 1, new QTableWidgetItem(list_addr.at(1)));
}

void StoreExampleMainWidget::onDealConnect(QString addr){
    ui->tbP2PConnectionOut->insertRow(0);
    QStringList list_addr = addr.split(':');
    ui->tbP2PConnectionOut->setItem(0, 0, new QTableWidgetItem(list_addr.at(0)));
    ui->tbP2PConnectionOut->setItem(0, 1, new QTableWidgetItem(list_addr.at(1)));
}

void StoreExampleMainWidget::onDealDisconnected(QString addr){
    QStringList list_addr = addr.split(':');
    int out_count = ui->tbP2PConnectionOut->rowCount();
    for(int i = 0; i < out_count; i++){
      if(ui->tbP2PConnectionOut->item(i, 0)->text() == list_addr.at(0)
         && ui->tbP2PConnectionOut->item(i, 1)->text() == list_addr.at(1)){
        ui->tbP2PConnectionOut->removeRow(i);
        break;
      }
    }

    int in_count = ui->tbP2PConnectionIn->rowCount();
    for(int i = 0; i < in_count; i++){
      if(ui->tbP2PConnectionIn->item(i, 0)->text() == list_addr.at(0)
         && ui->tbP2PConnectionIn->item(i, 1)->text() == list_addr.at(1)){
        ui->tbP2PConnectionIn->removeRow(i);
        break;
      }
    }
}

void StoreExampleMainWidget::on_btnPTSimTransSpeed_clicked(){
  QString str = ui->edtPTSimTransSpeed->text();
  uint32_t num = str.toUInt()<1?1:str.toInt();
  auto_trans_interval_ = num;
}

void StoreExampleMainWidget::on_btnStartAllTest_clicked(){
  on_btnMSVStart_1_clicked();
  on_btnMSVStart_2_clicked();
  on_btnMSVStart_3_clicked();
  on_btnMSVStart_4_clicked();
  on_btnMSVStart_5_clicked();
  on_btnMSVStart_6_clicked();

  on_btnMSVStartTrans_1_clicked();
  on_btnMSVStartTrans_2_clicked();
  on_btnMSVStartTrans_3_clicked();
  on_btnMSVStartTrans_4_clicked();
  on_btnMSVStartTrans_5_clicked();
  on_btnMSVStartTrans_6_clicked();
  ui->btnStartAllTest->setEnabled(false);
}

void StoreExampleMainWidget::on_btnForRemove_clicked(){
  ambr::core::UnitHash unit_hash(ui->edtForRemove->text().toStdString());
  std::string err;
  if(!store_manager_->RemoveUnit(unit_hash, &err)){
    ui->edtLogForRemove->setPlainText(err.c_str());
  }
}

void StoreExampleMainWidget::on_btnFlushValidatorIncome_clicked(){
  std::list<std::pair<ambr::core::PublicKey, ambr::store::ValidatorBalanceStore> > list = store_manager_->GetValidatorIncomeListForDebug();
  while(ui->tbValidatorIncome->rowCount()){
    ui->tbValidatorIncome->removeRow(0);
  }
  for(std::pair<ambr::core::PublicKey, ambr::store::ValidatorBalanceStore> item: list){
    ui->tbValidatorIncome->insertRow(0);
    ui->tbValidatorIncome->setItem(0, 0, new QTableWidgetItem(item.first.encode_to_hex().c_str()));
    ui->tbValidatorIncome->setItem(0, 1, new QTableWidgetItem(item.second.balance_.encode_to_dec().c_str()));
  }
}

void StoreExampleMainWidget::on_btnTextPrintAllBalance_clicked(){
  LOG(INFO)<<store_manager_->GetBalanceAllForDebug().encode_to_dec();
}

void StoreExampleMainWidget::on_btnShowAllUnitByValidator_clicked(){
  ambr::core::UnitHash unit_hash(ui->edtValidatorUnit->text().toStdString());
  std::list<std::shared_ptr<ambr::core::Unit> > list_unit = store_manager_->GetAllUnitByValidatorUnitHash(unit_hash);
  std::string str;
  for(std::shared_ptr<ambr::core::Unit> unit:list_unit){
    str+= unit->hash().encode_to_hex()+"\r\n";
  }
  ui->edtAllUnitByValidator->setPlainText(QString::fromStdString(str));
}

void StoreExampleMainWidget::on_btnPTSimValidateSpeed_clicked(){
  QString str = ui->edtPTSimValidateSpeed->text();
  uint32_t num = str.toUInt()>10000?10000:str.toInt();
  store_manager_->SetValidateUnitInterval(10001/(num+1));
}

void StoreExampleMainWidget::OnDrawTimerOut()
{
  ui->wgtPaint->update();
}

void StoreExampleMainWidget::OnTpsTimer(){
  static QTime time = QTime::currentTime();
  int len = time.msecsTo(QTime::currentTime());
  time = QTime::currentTime();
  ui->edtRunTimeTps->setText(QString::number(tps_count_*1000/((len==0)?1:len)));
  tps_count_ = 0;
}

void StoreExampleMainWidget::OnNetStateTimer(){
  ui->lblValidatorNonce->setText(QString::number(store_manager_->GetLastValidatedUnitNonce()));
  for(int i = 0; i < ui->tbP2PConnectionIn->rowCount(); i++){
    std::string str_addr = ui->tbP2PConnectionIn->item(i, 0)->text().toStdString()+":"+ui->tbP2PConnectionIn->item(i, 1)->text().toStdString();
    ui->tbP2PConnectionIn->setItem(i,2, new QTableWidgetItem(p_syn_manager->GetNodeIfPauseSend(str_addr)?"yes":"no"));
    ui->tbP2PConnectionIn->setItem(i,3, new QTableWidgetItem(p_syn_manager->GetNodeIfPauseReceive(str_addr)?"yes":"no"));
    ui->tbP2PConnectionIn->setItem(i,4, new QTableWidgetItem(QString::number(p_syn_manager->GetNodeNonce(str_addr))));
  }
  for(int i = 0; i < ui->tbP2PConnectionOut->rowCount(); i++){
    std::string str_addr = ui->tbP2PConnectionOut->item(i, 0)->text().toStdString()+":"+ui->tbP2PConnectionOut->item(i, 1)->text().toStdString();
    ui->tbP2PConnectionOut->setItem(i,2, new QTableWidgetItem(p_syn_manager->GetNodeIfPauseSend(str_addr)?"yes":"no"));
    ui->tbP2PConnectionOut->setItem(i,3, new QTableWidgetItem(p_syn_manager->GetNodeIfPauseReceive(str_addr)?"yes":"no"));
    ui->tbP2PConnectionOut->setItem(i,4, new QTableWidgetItem(QString::number(p_syn_manager->GetNodeNonce(str_addr))));
  }
}

void StoreExampleMainWidget::on_btnP2PStart_clicked(){
  p_syn_manager->SetOnAcceptNode(std::bind(&StoreExampleMainWidget::OnAcceptNode, this, std::placeholders::_1));
  p_syn_manager->SetOnConnectedNode(std::bind(&StoreExampleMainWidget::OnConnectNode, this, std::placeholders::_1));
  p_syn_manager->SetOnDisconnectNode(std::bind(&StoreExampleMainWidget::OnDisconnectedNode, this, std::placeholders::_1));

  ambr::syn::SynManagerConfig config;
  config.max_in_peer_ = 8;
  config.max_out_peer_ = 8;
  config.max_in_peer_for_optimize_ = 8;
  config.max_out_peer_for_optimize_ = 8;
  config.listen_port_ = ui->edtP2PListenPort->text().toInt();

  config.vec_seed_.push_back(ui->edtP2PSeedAddr->text().toStdString());
  config.use_upnp_ = false;
  config.use_nat_pmp_ = false;
  config.use_natp_ = false;
  config.heart_time_ = 88;
  std::thread tThread(&ambr::syn::SynManager::Init, p_syn_manager.get(), config);
  tThread.detach();
  ui->btnP2PStart->setEnabled(false);
}

void StoreExampleMainWidget::on_pushButton_clicked(){
  //CheckValidatorUnit();
  CreateDebugInitChain();
}

void StoreExampleMainWidget::on_btnPVAddCheck_clicked(){
  ui->lstPVCheck->addItem(ui->edtPVCheckHash->text());
}

void StoreExampleMainWidget::on_btnPVRemoveCheck_clicked(){
  if(ui->lstPVCheck->currentRow() != -1){
    QListWidgetItem* item = ui->lstPVCheck->currentItem();
    ui->lstPVCheck->removeItemWidget(item);
    delete item;
    //ui->lstPVCheck->clear();
  }
}

void StoreExampleMainWidget::on_btnPVAddVote_clicked(){
  ambr::core::VoteUnit unit;
  unit.set_version(0x00000001);
  unit.set_type(ambr::core::UnitType::Vote);
  ambr::core::PrivateKey pri_key;
  ambr::core::PublicKey pub_key;
  if(!pri_key.decode_from_hex(ui->edtPVVotePriKey->text().toStdString())){
    ui->edtPVLOG->setPlainText("private key decode error");
    return;
  }
  pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  unit.set_public_key(pub_key);
  ambr::core::UnitHash last_validator_hash;
  /*if(!store_manager_->GetLastValidateUnit(last_validator_hash)){
    ui->edtPVLOG->setPlainText("get last validator unit error");
    return;
  }*/
  unit.set_prev_unit(ui->edtPVPriKey->text().toStdString());
  bool accept = (ui->cbPVAccept->checkState()==Qt::Checked)?true:false;
  ambr::core::UnitHash validator_unit_hash;
  if(!validator_unit_hash.decode_from_hex(ui->edtPVArmHash->text().toStdString())){
    ui->edtPVLOG->setPlainText("validator unit hash decode error");
    return;
  }
  unit.set_accept(accept);
  unit.set_validator_unit_hash(validator_unit_hash);
  unit.CalcHashAndFill();
  unit.SignatureAndFill(pri_key);
  ui->lstPVVote->addItem(unit.SerializeJson().c_str());
  LOG(INFO)<<ui->lstPVVote->item(0)->text().toStdString();
}

void StoreExampleMainWidget::on_btnPVTime_clicked(){
  boost::posix_time::ptime pt = boost::posix_time::second_clock::universal_time();
  boost::posix_time::ptime pt_ori(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
  boost::posix_time::time_duration duration = pt-pt_ori;
  QString str_time = QString().sprintf("%ld", duration.total_seconds());
  ui->edtPVTime->setText(str_time);
}

void StoreExampleMainWidget::on_btnPVRemoveVote_clicked(){
  if(ui->lstPVVote->currentRow() != -1){
    QListWidgetItem* item = ui->lstPVVote->currentItem();
    ui->lstPVVote->removeItemWidget(item);
    delete item;
  }
}

void StoreExampleMainWidget::on_btnPVValidatorUnit_clicked(){
  std::shared_ptr<ambr::core::ValidatorUnit> unit = std::make_shared<ambr::core::ValidatorUnit>();
  unit->set_version(0x00000001);
  unit->set_type(ambr::core::UnitType::Validator);
  ambr::core::PrivateKey pri_key(ui->edtPVPriKey->text().toStdString());
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  unit->set_public_key(pub_key);
  unit->set_prev_unit(ambr::core::UnitHash(ui->edtPVPrvUnit->text().toStdString()));
  //unit->set_balance(const Amount& amount);
  for(int i = 0; i < ui->lstPVCheck->count(); i++){
    ambr::core::UnitHash hash(ui->lstPVCheck->item(i)->text().toStdString());
    unit->add_check_list(hash);
  }
  for(int i = 0; i < ui->lstPVVote->count(); i++){
    ambr::core::VoteUnit vote_unit;
    if(!vote_unit.DeSerializeJson(ui->lstPVVote->item(i)->text().toStdString())){
      return;
    }
    unit->add_vote_list(vote_unit);
    unit->add_vote_hash_list(vote_unit.hash());
  }

  unit->set_percent(0);
  unit->set_time_stamp(ui->edtPVTime->text().toULongLong());
  unit->set_nonce(ui->edtPVNonce->text().toULongLong());
  unit->CalcHashAndFill();
  unit->SignatureAndFill(pri_key);
  std::string str_err;
  if(store_manager_->AddValidateUnit(unit, &str_err)){
    std::vector<uint8_t>&& buf = unit->SerializeByte();
    std::string str_data;
    str_data.assign(buf.begin(), buf.end());
    ui->edtPVLOG->setPlainText(QString("Add validator unit success:")+unit->SerializeJson().c_str());
  }else{
    ui->edtPVLOG->setPlainText(QString("Add validator unit faild:")+str_err.c_str());
  }
}

void StoreExampleMainWidget::on_btnTranslateCashDisposite_clicked(){
  ambr::core::PrivateKey pri_key;
  pri_key.decode_from_hex(ui->edtTCPrivate->text().toStdString());
  ambr::core::Amount amount;
  amount.set_data((boost::multiprecision::uint128_t)ui->edtTCAmount->text().toULongLong());

  ambr::core::UnitHash tx_hash;
  std::shared_ptr<ambr::core::Unit> unit;
  std::string str_err;
  if(store_manager_->JoinValidatorSet(pri_key, amount, &tx_hash, unit, &str_err)){
    ui->edtTCPlainEdit->setPlainText(QString("Send success:")+unit->SerializeJson().c_str());
  }else{
    ui->edtTCPlainEdit->setPlainText(QString("Send Faild:")+str_err.c_str());
  }
}

void StoreExampleMainWidget::on_btnTranslateUnfreeze_clicked(){
  ambr::core::PrivateKey pri_key;
  pri_key.decode_from_hex(ui->edtTUPrivate->text().toStdString());
  ambr::core::UnitHash tx_hash;
  std::shared_ptr<ambr::core::Unit> unit;
  std::string str_err;
  if(store_manager_->LeaveValidatorSet(pri_key, &tx_hash, unit, &str_err)){
    ui->edtTCPlainEdit->setPlainText(QString("Send success:")+unit->SerializeJson().c_str());
  }else{
    ui->edtTCPlainEdit->setPlainText(QString("Send Faild:")+str_err.c_str());
  }
}

void StoreExampleMainWidget::StartPublishTrans(const ambr::core::PrivateKey &pri_key){
  std::shared_ptr<std::thread> thread;
  auto_publish_trans_thread_map_[pri_key] = std::pair<bool, std::shared_ptr<std::thread>>(true, thread);
  thread = std::make_shared<std::thread>(boost::bind(&StoreExampleMainWidget::AutoPublishTransThread, this, pri_key));
  auto_publish_trans_thread_map_[pri_key].second = thread;
}

void StoreExampleMainWidget::AutoPublishTransThread(const ambr::core::PrivateKey &pri_key){
  std::vector<ambr::core::PublicKey> pub_key_list = {
      ambr::core::GetPublicKeyByPrivateKey("25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC"),
      ambr::core::GetPublicKeyByPrivateKey("F49E1B9F671D0B244744E07289EA0807FAE09F8335F0C1B0629F1BF924CA64E1"),
      ambr::core::GetPublicKeyByPrivateKey("9812383BF3CE164A3D968186BEBA1CCFF299C9C59448A19BF3C0582336E01301"),
      ambr::core::GetPublicKeyByPrivateKey("29176270484F74852C5ABCBFEF26C4193FE4C2E4C522984D833329EDD502DC84"),
      ambr::core::GetPublicKeyByPrivateKey("C99FC6C3EF33BAB82A8DC27C3D6C26D90DFF3FBE1EB7BA6996A88662A34E031E"),
      ambr::core::GetPublicKeyByPrivateKey("C56E273AE386A16846D5710F2B04DE75DE5D4DD086D15ABBFF0B184BC01F81C5")};
  auto iter = std::find(pub_key_list.begin(), pub_key_list.end(), ambr::core::GetPublicKeyByPrivateKey(pri_key));
  if(iter != pub_key_list.end()){
    pub_key_list.erase(iter);
  }

  ambr::core::UnitHash tx_hash;
  std::shared_ptr<ambr::core::Unit> unit_sended;
  std::string err;
  while(auto_publish_trans_thread_map_[pri_key].first){
    ambr::core::Amount amount;
    if(store_manager_->GetBalanceByPubKey(ambr::core::GetPublicKeyByPrivateKey(pri_key), amount)){
      if(!store_manager_->SendToAddress(pub_key_list[qrand()%pub_key_list.size()], amount/10, pri_key, &tx_hash, unit_sended,&err)){
        std::cout<<"error:"<<err<<std::endl;
      }
    }
    std::list<ambr::core::UnitHash> wait_list = store_manager_->GetWaitForReceiveList(ambr::core::GetPublicKeyByPrivateKey(pri_key));
    for(ambr::core::UnitHash unit_hash: wait_list){
      if(!store_manager_->ReceiveFromUnitHash(unit_hash, pri_key, &tx_hash, unit_sended,&err)){
        std::cout<<"error:"<<err<<std::endl;
      }
    }
    boost::this_thread::sleep(boost::posix_time::millisec(qrand()%auto_trans_interval_));
  }
}

void StoreExampleMainWidget::StopPublishTrans(const ambr::core::PrivateKey &pri_key){
  auto iter = auto_publish_trans_thread_map_.find(pri_key);
  if(iter != auto_publish_trans_thread_map_.end()){
    auto_publish_trans_thread_map_[pri_key].first = false;
    auto_publish_trans_thread_map_[pri_key].second->join();
    auto_publish_trans_thread_map_.erase(pri_key);
  }
}
