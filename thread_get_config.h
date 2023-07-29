#ifndef THREAD_GET_CONFIG_H
#define THREAD_GET_CONFIG_H

#include <qthread.h>
#include<QDateTime>
class Thread_get_config : public QThread
{
public:
    void run();
    Thread_get_config(QObject* parent);
    ~Thread_get_config();
signals:

public slots:

};
#endif // THREAD_GET_CONFIG_H
