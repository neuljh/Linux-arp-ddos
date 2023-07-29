#include "mainwindow.h"
#include "ui_mainwindow.h"

#include"core.cpp"
#include"arp_attack.h"
#include"ddos_attack.h"

#include"data_all.h"

#include "dialog_all.h"
#include"libpcap9.cpp"


int Dialog_all::index=0;


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->tabWidget->setTabText(0,"Home page");
    ui->tabWidget->setTabText(1,"Packet sniffing I");
    ui->tabWidget->setTabText(2,"Data statistics");
    ui->tabWidget->setTabText(3,"Packet sniffing II");
    ui->tabWidget->setTabText(4,"ARP attack");
    ui->tabWidget->setTabText(5,"DDos attack");
    ui->tabWidget->setTabText(6,"Information collection");

    ui->tabWidget_sniff->setTabText(0,"Link Layer");
    ui->tabWidget_sniff->setTabText(1,"Network Layer");
    ui->tabWidget_sniff->setTabText(2,"Transport Layer");


    ui->stop_attack->setEnabled(false);
    ui->stop_get_packet->setEnabled(false);
    ARP_attack::attack_times=0;
    ARP_attack::log="";
    ARP_attack::log+="The software is successfully started!\n Wait for the service to initialize......\n";
    set_log(ARP_attack::log);

    ui->ddos_stop_attack->setEnabled(false);

    Data::datas.clear();
    vector<string> data_all_headers;
    data_all_headers.push_back("State");
    data_all_headers.push_back("Source IP Address");
    data_all_headers.push_back("Source Port/MAC Number");
    data_all_headers.push_back("Destination IP Address");
    data_all_headers.push_back("Destination Port/MAC Address");
    data_all_headers.push_back("Protocol");
    setTableWidget(ui->all_data_table,data_all_headers,512,data_all_headers.size());

    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(update_data_all()));
    timer->start(1000);

    //thread 1
    thread_get_config=new Thread_get_config(this);
    connect(ui->default_config,&QPushButton::clicked,this,&MainWindow::on_default_config_clicked);

    //thread2
    thread_exe_attack=new Thread_exe_attack(this);
    connect(this,&MainWindow::send_attack_ip_mac,thread_exe_attack,&Thread_exe_attack::recv_ip_mac);
    connect(ui->exe_attack,&QPushButton::clicked,this,&MainWindow::on_exe_attack_clicked);

    //thread3
    thread_scan=new Thread_scan(this);
    connect(ui->pushButton_3,&QPushButton::clicked,this,&MainWindow::on_pushButton_3_clicked);

    //thread4
    thread_ddos_attack=new Thread_ddos_attack(this);
    connect(ui->ddos_exe_attack,&QPushButton::clicked,this,&MainWindow::on_ddos_exe_attack_clicked);
    connect(this,&MainWindow::send_data_to_ddos,thread_ddos_attack,&Thread_ddos_attack::recv_data_from_main);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_3_clicked()//run now
{
    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy-MM-dd hh:mm::ss.zzz");
    cout<<"main thread scan: "<<current_date.toStdString()<<endl;
    bool sign=true;
    Core::stop=false;
    ui->pushButton_3->setEnabled(false);// make pushbutton3 unable to activate
    ui->stop_get_packet->setEnabled(true);// make stopbutton able to activate

    if(ui->cb_all->isChecked()){
        f.a=true;
    }
    if(ui->cb_eth->isChecked()){
        f.e=true;
    }
    if(ui->cb_dump->isChecked()){
        f.d=true;
    }
    if(ui->cb_help->isChecked()){
        Core::help();
        //ui->tb_res->setText(QString::fromStdString(Core::res));
        sign=false;
        //exit(1);
    }
    if(ui->te_ifname->toPlainText().length()!=0){
        f.i=true;
        if(ui->te_ifname->toPlainText().length()<IFRLEN){
            strcpy(f.ifname,ui->te_ifname->toPlainText().toStdString().c_str());
        }else{
            printf("the size of the ifname is too big\n");
            QMessageBox::question(this,"Prompt information","The size of the ifname is too big!");
            sign=false;
        }
    }
    if(ui->cb_arp->isChecked()||ui->cb_ip->isChecked()||ui->cb_tcp->isChecked()||ui->cb_udp->isChecked()||ui->cb_icmp->isChecked()){
        f.p=true;
        if(ui->cb_arp->isChecked()){
            p.arp=true;
        }
        if(ui->cb_ip->isChecked()){
            p.ip=true;
        }
        if(ui->cb_tcp->isChecked()){
            p.tcp=true;
        }
        if(ui->cb_udp->isChecked()){
            p.udp=true;
        }
        if(ui->cb_icmp->isChecked()){
            p.icmp=true;
        }
    }
    if(ui->te_ip->toPlainText().length()!=0&&ui->te_port->toPlainText().length()!=0){
        if(Core::ip_atou(ui->te_ip->toPlainText().toUtf8().data(),&pf.ip)==0){
            if(atoi(ui->te_port->toPlainText().toStdString().c_str())>0){
                f.f=true;
                pf.i=true;
                pf.p=true;
                pf.port=atoi(ui->te_port->toPlainText().toStdString().c_str());
            }
        }

    }//fill in the data struct
    if(sign){
        thread_scan->start();
        QThread::sleep(1);
    }//make thread run
}

void MainWindow::on_pb_default_clicked()
{
    ui->cb_help->setChecked(false);
    ui->cb_ip->setChecked(true);
    ui->cb_arp->setChecked(false);
    ui->cb_tcp->setChecked(true);
    ui->cb_udp->setChecked(false);
    ui->cb_icmp->setChecked(false);
    ui->cb_all->setChecked(false);
    ui->cb_dump->setChecked(true);
    ui->cb_eth->setChecked(true);
}

void MainWindow::on_pb_reset_clicked()
{
    ui->cb_help->setChecked(false);
    ui->cb_ip->setChecked(false);
    ui->cb_arp->setChecked(false);
    ui->cb_tcp->setChecked(false);
    ui->cb_udp->setChecked(false);
    ui->cb_icmp->setChecked(false);
    ui->cb_all->setChecked(false);
    ui->cb_dump->setChecked(false);
    ui->cb_eth->setChecked(false);
}

void MainWindow::on_pb_clear_clicked()
{
    ui->tb_res->setText("");
}

void MainWindow::on_cb_help_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked) // "选中"
    {
        QMessageBox::information(this,"Prompt information","Network sniffing function, required fields: Protocol filter, Other options; Optional fields:ifname,IP Address,Port number!");

        ui->cb_ip->setChecked(false);
        ui->cb_arp->setChecked(false);
        ui->cb_tcp->setChecked(false);
        ui->cb_udp->setChecked(false);
        ui->cb_icmp->setChecked(false);
        ui->cb_all->setChecked(false);
        ui->cb_dump->setChecked(false);
        ui->cb_eth->setChecked(false);

        ui->cb_ip->setEnabled(false);
        ui->cb_arp->setEnabled(false);
        ui->cb_tcp->setEnabled(false);
        ui->cb_udp->setEnabled(false);
        ui->cb_icmp->setEnabled(false);
        ui->cb_all->setEnabled(false);
        ui->cb_dump->setEnabled(false);
        ui->cb_eth->setEnabled(false);
        //选中执行函数
    }
    else                   // 未选中 - Qt::Unchecked
    {
        ui->cb_ip->setEnabled(true);
        ui->cb_arp->setEnabled(true);
        ui->cb_tcp->setEnabled(true);
        ui->cb_udp->setEnabled(true);
        ui->cb_icmp->setEnabled(true);
        ui->cb_all->setEnabled(true);
        ui->cb_dump->setEnabled(true);
        ui->cb_eth->setEnabled(true);
       //未选中执行函数
    }

}


void MainWindow::on_pushButton_clicked()
{
    if(Core::start_time.size()==0&&
            Core::end_time.size()==0&&
            Core::mac_board.size()==0&&
            Core::mac_short.size()==0&&
            Core::mac_long.size()==0&&
            Core::mac_byte.size()==0&&
            Core::mac_packet.size()==0&&
            Core::mac_byte_speed.size()==0&&
            Core::mac_packet_speed.size()==0&&
            Core::ip_broadcast.size()==0&&
            Core::ip_byte.size()==0&&
            Core::ip_packet.size()==0&&
            Core::udp_packet.size()==0&&
            Core::icmp_packet.size()==0&&
            Core::icmp_redir.size()==0&&
            Core::icmp_des.size()==0&&
            Core::bit_s.size()==0){
        QMessageBox::information(this,"Prompt information","No packets detected!");
    }

    ui->tb_start_time->setText(QString::fromStdString(Core::start_time));
    ui->tb_end_time->setText(QString::fromStdString(Core::end_time));
    ui->tb_mac_broad->setText(QString::fromStdString(Core::mac_board));
    ui->tb_mac_short->setText(QString::fromStdString(Core::mac_short));
    ui->tb_mac_long->setText(QString::fromStdString(Core::mac_long));
    ui->tb_mac_byte->setText(QString::fromStdString(Core::mac_byte));
    ui->tb_mac_oacket->setText(QString::fromStdString(Core::mac_packet));
    ui->tb_mac_byte_speed->setText(QString::fromStdString(Core::mac_byte_speed));
    ui->tb_packet_speed->setText(QString::fromStdString(Core::mac_packet_speed));
    ui->tb_ip_broadcast->setText(QString::fromStdString(Core::ip_broadcast));
    ui->tb_ip_byte->setText(QString::fromStdString(Core::ip_byte));
    ui->tb_ip_packet->setText(QString::fromStdString(Core::ip_packet));
    ui->tb_udp_packet->setText(QString::fromStdString(Core::udp_packet));
    ui->tb_icmp_packet->setText(QString::fromStdString(Core::icmp_packet));
    ui->tb_icmp_red->setText(QString::fromStdString(Core::icmp_redir));
    ui->tb_icmp_des->setText(QString::fromStdString(Core::icmp_des));
    ui->tb_icmp_bits->setText(QString::fromStdString(Core::bit_s));
}

//2023.03.01new

void MainWindow::set_log(string log){
    ui->log_container->setText(QString::fromStdString(log));
}

void MainWindow::set_packet_data(string log){
    ui->tb_res->setText(QString::fromStdString(log));
}

void MainWindow::set_ddos_log(string log){
    ui->ddos_log->setText(QString::fromStdString(log));
}

void MainWindow::on_default_config_clicked()
{
    thread_get_config->start();
    QThread::sleep(2);

    ui->ip_attack->setPlainText("192.168.176.134");
    ui->mac_attack->setPlainText("00:0c:29:d5:73:ea");

    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy-MM-dd hh:mm::ss.zzz");

    cout<<"main thread get_default_config: "<<current_date.toStdString()<<endl;
    ARP_attack::log+="\n The device was initialized successfully!\n";
    //ARP_attack::log+="The "+to_string(ARP_attack::attack_times)+" times ARP Attacking is preparing now......"+"\n"+"Basic functions are being configured"+"\n";

//    ARP_cpp arp_cpp;
//    arp_cpp.get_default_config();//need thread

    string recommend_net_inter=ARP_attack::network_interface_all.at(0);
    string ip=ARP_attack::local_ip_all.at(0);
    string mac=ARP_attack::local_mac_all.at(0);

    string recommend_net_inter_text=recommend_net_inter+"recommended";
    ui->recom_net_interface->setText(QString::fromStdString(recommend_net_inter_text));
    ui->local_ip->setText(ip.c_str());
    ui->local_mac->setText(mac.c_str());

    for(int index=0;index<ARP_attack::network_interface_all.size();index++){
        if(index==0){
            ui->all_net_adapters->addItem(recommend_net_inter.c_str());
        }else{
            ui->all_net_adapters->addItem(ARP_attack::network_interface_all.at(index).c_str());
        }

    }
    ARP_attack::log+="***********************\n";
    ARP_attack::log+="Recommendation interface: "+recommend_net_inter+"\n";
    ARP_attack::log+="Local IP Address: "+ip+"\n";
    ARP_attack::log+="Local MAC Address: "+mac+"\n";
    ARP_attack::log+="***********************\n\n";
    //get basic infor

    //arp_cpp.get_arp_table();//need thread
    vector<string> arp_table_headers;
    //header<< tr("ID") <<tr("IP Address")<< tr("HW Type") << tr("Flags") << tr("HW Address") << tr("Mask") << "Device" ;
    arp_table_headers.push_back("ID");
    arp_table_headers.push_back("IP Address");
    arp_table_headers.push_back("HW Type");
    arp_table_headers.push_back("Flags");
    arp_table_headers.push_back("HW Address");
    arp_table_headers.push_back("Mask");
    arp_table_headers.push_back("Device");
    setTableWidget(ui->arp_table,arp_table_headers,50,7);
    //ui->arp_table->setItem(0,0,new QTableWidgetItem(QString::fromStdString("HELLO")));
    //cout<<"111"<<endl;
    int id=1;
    int useless_num=9;
    for(int index=0;index<ARP_attack::devices.size();index++){
        for(int j=0;j<(ARP_attack::contents.size()-9)/(ARP_attack::devices.size())+1;j++){
            if(j==0){
                ui->arp_table->setItem(index,j,new QTableWidgetItem(QString::fromStdString(to_string(id))));//QTableWidgetItem
                id++;
            }else{
                //cout<<useless_num+j-1<<endl;
                ui->arp_table->setItem(index,j,new QTableWidgetItem(QString::fromStdString(ARP_attack::contents.at(useless_num+j-1))));
            }

        }
        useless_num+=(ARP_attack::contents.size()-9)/(ARP_attack::devices.size());
    }

    ui->default_config->setEnabled(false);

    ARP_attack::log+="Loading the ARP cache table successfully!\n ";
    set_log(ARP_attack::log);
    ui->arp_dump->setText(QString::fromStdString(ARP_attack::arp_dump));
}

//QTableWidget的初始化
void MainWindow::setTableWidget(QTableWidget* table,vector<string> &headers,int row,int column)
{
    table->resizeRowsToContents();//调整行内容大小
    table->setColumnCount(column);//设置列数
    table->setRowCount(row);//设置行数
    table->horizontalHeader()->setDefaultSectionSize(200);//标题头的大小
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);//横向先自适应宽度
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);//然后设置要根据内容使用宽度的列
    //设置标题头的文字
    QStringList header;
    for(int index=0;index<headers.size();index++){
        header<<tr(headers.at(index).c_str());
    }
    table->setHorizontalHeaderLabels(header);
    //设置标题头的字体样式
    QFont font = ui->arp_table->horizontalHeader()->font();
    font.setBold(true);
    table->horizontalHeader()->setFont(font);
    table->horizontalHeader()->setStretchLastSection(true); //设置充满表宽度
    table->verticalHeader()->setDefaultSectionSize(10); //设置行距
    table->setFrameShape(QFrame::NoFrame); //设置无边框
    table->setShowGrid(true); //设置不显示格子线
    table->verticalHeader()->setVisible(false); //设置行号列,true为显示
    table->setSelectionMode(QAbstractItemView::ExtendedSelection); //可多选（Ctrl、Shift、 Ctrl+A都可以）
    table->setSelectionBehavior(QAbstractItemView::SelectRows); //设置选择行为时每次选择一行
    table->setEditTriggers(QAbstractItemView::NoEditTriggers); //设置不可编辑
    table->horizontalHeader()->resizeSection(0,100);//设置表头第一列的宽度为100
    table->horizontalHeader()->setFixedHeight(30); //设置表头的高度
    table->setStyleSheet("selection-background-color:lightblue;"); //设置选中背景色
    table->horizontalHeader()->setStyleSheet("QHeaderView::section{background:white;}"); //设置表头背景色
    //设置水平、垂直滚动条样式,添加头文件 #include <QScrollBar>
    table->horizontalScrollBar()->setStyleSheet("QScrollBar{background:transparent; height:10px;}"
                                                          "QScrollBar::handle{background:lightgray; border:2px solid transparent; border-radius:5px;}"
                                                          "QScrollBar::handle:hover{background:gray;}"
                                                          "QScrollBar::sub-line{background:transparent;}"
                                                          "QScrollBar::add-line{background:transparent;}");
    table->verticalScrollBar()->setStyleSheet("QScrollBar{background:transparent; width: 10px;}"
                                                        "QScrollBar::handle{background:lightgray; border:2px solid transparent; border-radius:5px;}"
                                                        "QScrollBar::handle:hover{background:gray;}"
                                                        "QScrollBar::sub-line{background:transparent;}"
                                                        "QScrollBar::add-line{background:transparent;}");
    table->clearContents();//清除表格数据区的所有内容，但是不清除表头
}

void MainWindow::on_arp_table_itemClicked(QTableWidgetItem *item)
{
    //获取当前点击的单元格的指针
    QTableWidgetItem* curItem = ui->arp_table->currentItem();
    //获取单元格内的内容
    QString wellName = curItem->text();
    //cout<<wellName.toStdString()<<endl;
    int order=-1;
    int real_order=ui->arp_table->currentRow();
    for(int index=0;index<ARP_attack::ips.size();index++){
        if(wellName.toStdString()==ARP_attack::ips.at(index)||
                wellName.toStdString()==ARP_attack::flags.at(index)||
                wellName.toStdString()==ARP_attack::masks.at(index)||
                wellName.toStdString()==ARP_attack::devices.at(index)||
                wellName.toStdString()==ARP_attack::hw_type.at(index)||
                wellName.toStdString()==ARP_attack::hw_address.at(index)){
            if(real_order==index){
                order=index;
                break;
            }

        }
    }
    ui->ip_spoof->setText((ARP_attack::ips.at(order).c_str()));
    ARP_attack::log+="\n Select information about the corresponding ARP cache table.\n";
    set_log(ARP_attack::log);
}


void MainWindow::on_exe_attack_clicked()
{

    //thread_exe_attack->start();
    //QThread::sleep(2);

    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy-MM-dd hh:mm::ss.zzz");
    cout<<"main thread exe_attack: "<<current_date.toStdString()<<endl;

//    QString ip_spoof=ui->ip_attack->document()->toPlainText();
//    QString mac_spoof=ui->mac_attack->document()->toPlainText();

    char* interface_str=(char*)malloc(100*sizeof(char));
    char* dest_ip_str=(char*)malloc(100*sizeof(char));
    char* dest_mac_str=(char*)malloc(100*sizeof(char));
    char* source_ip_str=(char*)malloc(100*sizeof(char));
    char* source_mac_str=(char*)malloc(100*sizeof(char));


    strcpy(interface_str,ui->all_net_adapters->currentText().toStdString().c_str());
    strcpy(dest_ip_str,ui->ip_attack->document()->toPlainText().toStdString().c_str());
    strcpy(dest_mac_str,ui->mac_attack->document()->toPlainText().toStdString().c_str());
    strcpy(source_ip_str,ui->ip_spoof->document()->toPlainText().toStdString().c_str());
    strcpy(source_mac_str,ui->mac_spoof->document()->toPlainText().toStdString().c_str());

    bool sign=true;
    if(strlen(interface_str) == 0||strlen(dest_mac_str) == 0||strlen(dest_ip_str) == 0||strlen(source_mac_str) == 0||strlen(source_ip_str) == 0){
        QMessageBox::warning(this,tr("Warning message"),tr("It is detected that part of the data is not complete, please fill in again!"));
        sign=false;
    }
    if(sign){
        ui->exe_attack->setEnabled(false);
        ui->stop_attack->setEnabled(true);
    }
    if(sign){
        vector<string> ip_mac;
        ip_mac.push_back(ui->all_net_adapters->currentText().toStdString());
        ip_mac.push_back(ui->ip_attack->document()->toPlainText().toStdString());
        ip_mac.push_back(ui->mac_attack->document()->toPlainText().toStdString());
        ip_mac.push_back(ui->ip_spoof->document()->toPlainText().toStdString());
        ip_mac.push_back(ui->mac_spoof->document()->toPlainText().toStdString());
        connect(ui->exe_attack,&QPushButton::clicked,[=](){
            emit send_attack_ip_mac(ip_mac);
            thread_exe_attack->start();
        });//send data????
    }
    set_log(ARP_attack::log);
}

void MainWindow::on_stop_attack_clicked()
{
    if(ARP_attack::infinite_loop==1){
        ARP_attack::infinite_loop=0;
        ui->exe_attack->setEnabled(true);
        ARP_attack::log+="\n The "+to_string(ARP_attack::attack_times)+" times ARP Attacking is cancelled!\n";
    }
    ui->arp_dump->setText(QString::fromStdString(ARP_attack::arp_dump));
}

void MainWindow::on_clear_log_clicked()
{
    ui->log_container->clear();
}

void MainWindow::on_stop_get_packet_clicked()
{
    Core::stop=true;
    Core::p_table();
    ui->pushButton_3->setEnabled(true);
    ui->stop_get_packet->setEnabled(false);
    set_packet_data(Core::res);
}

void MainWindow::on_ddos_default_config_clicked()
{
    ui->local_ip_2->setText("192.168.176.132");
    ui->local_mac_2->setText("00:0c:29:fc:1b:76");
    ui->ddos_attack_ip->setText("192.168.176.134");
    ui->ddos_attack_port->setText("8080");

    QButtonGroup* group=new QButtonGroup(this);
    group->addButton(ui->ddos_syn,0);
    group->addButton(ui->ddos_rst,1);

    ui->ddos_syn->setChecked(true);
    ui->ddos_rst->setChecked(false);
}

void MainWindow::on_ddos_exe_attack_clicked()
{

    DDOS_Attack::sending=true;
    ui->ddos_exe_attack->setEnabled(false);
    ui->ddos_stop_attack->setEnabled(true);

    vector<string> data;
//    data.push_back(ui->local_ip_2->toPlainText().toStdString());
//    data.push_back(ui->local_mac_2->toPlainText().toStdString());
    data.push_back(ui->ddos_attack_ip->toPlainText().toStdString());
    data.push_back(ui->ddos_attack_port->toPlainText().toStdString());
    if(ui->ddos_syn->isChecked()){
        data.push_back("true");
    }else{
        data.push_back("false");
    }
    emit send_data_to_ddos(data);
    thread_ddos_attack->start();





}

void MainWindow::on_ddos_stop_attack_clicked()
{
    set_ddos_log(DDOS_Attack::ddos_log);
    if(DDOS_Attack::sending){
        DDOS_Attack::sending=false;
        ui->ddos_exe_attack->setEnabled(true);
        ui->ddos_stop_attack->setEnabled(false);

    }

}

void MainWindow::on_ddos_clear_log_clicked()
{
    ui->ddos_log->clear();
}

void MainWindow::on_all_data_clear_clicked()
{
    Data::datas.clear();
    ui->all_data_table->clearContents();
}

void MainWindow::update_data_all(){
    for(int row=0;row<Data::datas.size();row++){
        for(int index=0;index<6;index++){
            ui->all_data_table->setItem(row,index,new QTableWidgetItem(QString::fromStdString(Data::datas.at(row)->get_attr(index))));
        }
    }
}

void MainWindow::on_pushButton_2_clicked()
{
    QString number_string=ui->number->toPlainText();
    int number;
    if(number_string==""){
        number=1;
    }else{
        number=number_string.toInt();
    }
     libpcap9::number=number;

     libpcap9::solution();

     ui->type_id->setText(libpcap9::ethernet_type[Dialog_all::index].c_str());
     ui->mac_source->setText(libpcap9::mac_source[Dialog_all::index].c_str());
     ui->mac_des->setText(libpcap9::mac_des[Dialog_all::index].c_str());

     ui->arp_ht->setText(to_string(libpcap9::hardware_type[Dialog_all::index]).c_str());
     ui->arp_pt->setText(to_string(libpcap9::protocol_type[Dialog_all::index]).c_str());
     ui->arp_hl->setText(to_string(libpcap9::hardware_length[Dialog_all::index]).c_str());
     ui->arp_pl->setText(to_string(libpcap9::protocol_length[Dialog_all::index]).c_str());
     ui->arp_operation->setText(to_string(libpcap9::operation_code[Dialog_all::index]).c_str());
     ui->eth_source->setText(libpcap9::eth_source[Dialog_all::index].c_str());
     ui->ip_source->setText(libpcap9::ip_source[Dialog_all::index].c_str());
     ui->eth_des->setText(libpcap9::eth_des[Dialog_all::index].c_str());
     ui->ip_des->setText(libpcap9::ip_des[Dialog_all::index].c_str());

     ui->ip_version->setText(to_string(libpcap9::ip_version[Dialog_all::index]).c_str());
     ui->ip_offset->setText(to_string(libpcap9::ip_offset[Dialog_all::index]).c_str());
     ui->ip_hl->setText(to_string(libpcap9::ip_header_length[Dialog_all::index]).c_str());
     ui->ip_ttl->setText(to_string(libpcap9::ip_ttl[Dialog_all::index]).c_str());
     ui->ip_tl->setText(to_string(libpcap9::ip_total_length[Dialog_all::index]).c_str());
     ui->ip_tos->setText(to_string(libpcap9::ip_tos[Dialog_all::index]).c_str());
     ui->ip_id->setText(to_string(libpcap9::ip_id[Dialog_all::index]).c_str());
     ui->ip_protocol->setText(to_string(libpcap9::ip_protocol[Dialog_all::index]).c_str());
     ui->ip_hc->setText(to_string(libpcap9::ip_checksum[Dialog_all::index]).c_str());
     ui->ip_source_address->setText(libpcap9::ip_source_address[Dialog_all::index].c_str());
     ui->ip_des_address->setText(libpcap9::ip_des_adddress[Dialog_all::index].c_str());

     ui->tcp_source_port->setText(to_string(libpcap9::tcp_source_port[Dialog_all::index]).c_str());
     ui->tcp_hl->setText(to_string(libpcap9::tcp_header_length[Dialog_all::index]).c_str());
     ui->tcp_des_port->setText(to_string(libpcap9::tcp_des_port[Dialog_all::index]).c_str());
     ui->tcp_reserved->setText(to_string(libpcap9::tcp_reserved[Dialog_all::index]).c_str());
     ui->tcp_seq_num->setText(to_string(libpcap9::tcp_seq_num[Dialog_all::index]).c_str());
     ui->tcp_flags->setText(libpcap9::tcp_flags[Dialog_all::index].c_str());
     ui->tcp_ack_num->setText(to_string(libpcap9::tcp_ack_num[Dialog_all::index]).c_str());
     ui->tcp_win_size->setText(to_string(libpcap9::tcp_win_size[Dialog_all::index]).c_str());
     ui->tcp_checksum->setText(to_string(libpcap9::tcp_checksum[Dialog_all::index]).c_str());
     ui->tcp_u_pointer->setText(to_string(libpcap9::tcp_u_pointer[Dialog_all::index]).c_str());
     ui->tcp_protocol->setText(libpcap9::tcp_protocol[Dialog_all::index].c_str());

     ui->udp_source_port->setText(to_string(libpcap9::udp_source_port[Dialog_all::index]).c_str());
     ui->udp_des_port->setText(to_string(libpcap9::udp_des_port[Dialog_all::index]).c_str());
     ui->udp_length->setText(to_string(libpcap9::udp_length[Dialog_all::index]).c_str());
     ui->udp_checksum->setText(to_string(libpcap9::udp_checksum[Dialog_all::index]).c_str());
     ui->udp_service->setText(libpcap9::udp_service[Dialog_all::index].c_str());

     ui->icmp_type->setText(to_string(libpcap9::icmp_type[Dialog_all::index]).c_str());
     ui->icmp_code->setText(to_string(libpcap9::icmp_code[Dialog_all::index]).c_str());
     ui->icmp_checksum->setText(to_string(libpcap9::icmp_checksum[Dialog_all::index]).c_str());
     ui->icmp_ids->setText(to_string(libpcap9::icmp_ids[Dialog_all::index]).c_str());
     ui->icmp_seq_num->setText(to_string(libpcap9::icmp_seq_num[Dialog_all::index]).c_str());
     ui->icmp_protocol->setText(libpcap9::icmp_protocol[Dialog_all::index].c_str());

     string str="The "+to_string(Dialog_all::index+1)+" packet is captured(Total: "+to_string(libpcap9::number)+" )";
     ui->order->setText(str.c_str());
}

void MainWindow::on_btn_next_clicked()
{
    Dialog_all::index++;
    if(Dialog_all::index==libpcap9::number){
        Dialog_all::index=0;
    }

    string str="The "+to_string(Dialog_all::index+1)+" packet is captured(Total: "+to_string(libpcap9::number)+" )";
    ui->order->setText(str.c_str());

    ui->type_id->setText(libpcap9::ethernet_type[Dialog_all::index].c_str());
    ui->mac_source->setText(libpcap9::mac_source[Dialog_all::index].c_str());
    ui->mac_des->setText(libpcap9::mac_des[Dialog_all::index].c_str());

    ui->arp_ht->setText(to_string(libpcap9::hardware_type[Dialog_all::index]).c_str());
    ui->arp_pt->setText(to_string(libpcap9::protocol_type[Dialog_all::index]).c_str());
    ui->arp_hl->setText(to_string(libpcap9::hardware_length[Dialog_all::index]).c_str());
    ui->arp_pl->setText(to_string(libpcap9::protocol_length[Dialog_all::index]).c_str());
    ui->arp_operation->setText(to_string(libpcap9::operation_code[Dialog_all::index]).c_str());
    ui->eth_source->setText(libpcap9::eth_source[Dialog_all::index].c_str());
    ui->ip_source->setText(libpcap9::ip_source[Dialog_all::index].c_str());
    ui->eth_des->setText(libpcap9::eth_des[Dialog_all::index].c_str());
    ui->ip_des->setText(libpcap9::ip_des[Dialog_all::index].c_str());

    ui->ip_version->setText(to_string(libpcap9::ip_version[Dialog_all::index]).c_str());
    ui->ip_offset->setText(to_string(libpcap9::ip_offset[Dialog_all::index]).c_str());
    ui->ip_hl->setText(to_string(libpcap9::ip_header_length[Dialog_all::index]).c_str());
    ui->ip_ttl->setText(to_string(libpcap9::ip_ttl[Dialog_all::index]).c_str());
    ui->ip_tl->setText(to_string(libpcap9::ip_total_length[Dialog_all::index]).c_str());
    ui->ip_tos->setText(to_string(libpcap9::ip_tos[Dialog_all::index]).c_str());
    ui->ip_id->setText(to_string(libpcap9::ip_id[Dialog_all::index]).c_str());
    ui->ip_protocol->setText(to_string(libpcap9::ip_protocol[Dialog_all::index]).c_str());
    ui->ip_hc->setText(to_string(libpcap9::ip_checksum[Dialog_all::index]).c_str());
    ui->ip_source_address->setText(libpcap9::ip_source_address[Dialog_all::index].c_str());
    ui->ip_des_address->setText(libpcap9::ip_des_adddress[Dialog_all::index].c_str());

    ui->tcp_source_port->setText(to_string(libpcap9::tcp_source_port[Dialog_all::index]).c_str());
    ui->tcp_hl->setText(to_string(libpcap9::tcp_header_length[Dialog_all::index]).c_str());
    ui->tcp_des_port->setText(to_string(libpcap9::tcp_des_port[Dialog_all::index]).c_str());
    ui->tcp_reserved->setText(to_string(libpcap9::tcp_reserved[Dialog_all::index]).c_str());
    ui->tcp_seq_num->setText(to_string(libpcap9::tcp_seq_num[Dialog_all::index]).c_str());
    ui->tcp_flags->setText(libpcap9::tcp_flags[Dialog_all::index].c_str());
    ui->tcp_ack_num->setText(to_string(libpcap9::tcp_ack_num[Dialog_all::index]).c_str());
    ui->tcp_win_size->setText(to_string(libpcap9::tcp_win_size[Dialog_all::index]).c_str());
    ui->tcp_checksum->setText(to_string(libpcap9::tcp_checksum[Dialog_all::index]).c_str());
    ui->tcp_u_pointer->setText(to_string(libpcap9::tcp_u_pointer[Dialog_all::index]).c_str());
    ui->tcp_protocol->setText(libpcap9::tcp_protocol[Dialog_all::index].c_str());

    ui->udp_source_port->setText(to_string(libpcap9::udp_source_port[Dialog_all::index]).c_str());
    ui->udp_des_port->setText(to_string(libpcap9::udp_des_port[Dialog_all::index]).c_str());
    ui->udp_length->setText(to_string(libpcap9::udp_length[Dialog_all::index]).c_str());
    ui->udp_checksum->setText(to_string(libpcap9::udp_checksum[Dialog_all::index]).c_str());
    ui->udp_service->setText(libpcap9::udp_service[Dialog_all::index].c_str());

    ui->icmp_type->setText(to_string(libpcap9::icmp_type[Dialog_all::index]).c_str());
    ui->icmp_code->setText(to_string(libpcap9::icmp_code[Dialog_all::index]).c_str());
    ui->icmp_checksum->setText(to_string(libpcap9::icmp_checksum[Dialog_all::index]).c_str());
    ui->icmp_ids->setText(to_string(libpcap9::icmp_ids[Dialog_all::index]).c_str());
    ui->icmp_seq_num->setText(to_string(libpcap9::icmp_seq_num[Dialog_all::index]).c_str());
    ui->icmp_protocol->setText(libpcap9::icmp_protocol[Dialog_all::index].c_str());
}
