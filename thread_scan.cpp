#include"thread_scan.h"
#include"qdebug.h"
#include"core.h"
Thread_scan::Thread_scan(QObject* parent){

}

void Thread_scan::run(){
    Core::init();
    //qDebug()<<"sub thread get_default_config";
    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy-MM-dd hh:mm::ss.zzz");
    cout<<"sub thread scan: "<<current_date.toStdString()<<endl;
    cout<< "sub thread ID:" << QThread::currentThreadId()<<endl;

    Core::solution();
}

Thread_scan::~Thread_scan(){
    quit();
}
