#include"thread_ddos_attack.h"
#include"qdebug.h"
#include"ddos_attack.h"

Thread_ddos_attack::Thread_ddos_attack(QObject* parent){

}

void Thread_ddos_attack::recv_data_from_main(const vector<string> &data_temp){
    data.assign(data_temp.begin(),data_temp.end());
}

void Thread_ddos_attack::run(){
    DDOS_Attack::init();
    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy-MM-dd hh:mm::ss.zzz");
    cout<<"sub thread ddos_attack: "<<current_date.toStdString()<<endl;
    cout<< "sub thread ID:" << QThread::currentThreadId()<<endl;

    string des_ip_string=data.at(0);
    char* des_ip=new char[des_ip_string.size()+1];
    des_ip_string.copy(des_ip,des_ip_string.size(),0);
    int des_port=atoi(data.at(1).c_str());
    bool sign=true;
    if(data.at(2)=="false"){
        sign=false;
    }
    DDOS_Attack::solution(des_ip,des_port,sign);


}

Thread_ddos_attack::~Thread_ddos_attack(){
    quit();
}
