#ifndef _UTIL_H_LOG
#define _UTIL_H_LOG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <ctime>
#include <pthread.h>

#define LOG(level,format,...) CLog::GetInstance()->WriteLog(__FUNCTION__,__FILE__, __LINE__, level,format,##__VA_ARGS__)
#define LOG_RAW(format,...) CLog::GetInstance()->WriteRawLog(format,##__VA_ARGS__)

enum LOG_LEVEL
{
    DEBUG =   0,
    WARNING = 1,
    ERROR =   2
};
class CLog
{
public:
    static CLog* GetInstance();
    void WriteLog(const char* func, const char* codeFile, long codeLine,int level, const char* format,...);
    void WriteRawLog(const char* format,...);
    void SpecifyLogfilename(const char *logfilename);
private:
    CLog(const char *logfile = "/tmp/li.log");
    ~CLog();
    CLog(CLog const&);            // Don't Implement
    void operator=(CLog const&); // Don't implement
    FILE* m_logfile;
    static CLog* instance;
    pthread_mutex_t mutex_x;

    class CGarbo
    {
    public:
        ~CGarbo()
        {
            if(CLog::instance)
            {
                delete CLog::instance;
                CLog::instance = NULL;
            }
        }
    };
    static CGarbo m_garbo;

};

#endif
