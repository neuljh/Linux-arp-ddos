
#include"thread_get_config.h"
#include"qdebug.h"
#include"arp_attack.h"
Thread_get_config::Thread_get_config(QObject* parent){

}

void Thread_get_config::run(){
    ARP_attack::init();
    //qDebug()<<"sub thread get_default_config";
    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy-MM-dd hh:mm::ss.zzz");
    cout<<"sub thread get_default_config: "<<current_date.toStdString()<<endl;
    cout<< "sub thread ID:" << QThread::currentThreadId()<<endl;

    ARP_attack::get_default_config();
    ARP_attack::get_arp_table();

}

Thread_get_config::~Thread_get_config(){
    quit();
}
