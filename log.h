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

enum LOG_LEVEL
{
    DEBUG =   0,
    WARNING = 1,
    ERROR =   2
};
static const char* log_level_array[] = {"DEBUG","WARNING","ERROR"};
class CLog
{
public:
    static CLog* GetInstance(const char* logfile = "/tmp/li.log");
    void WriteLog(const char* func, const char* codeFile, long codeLine,int level, const char* format,...);
private:
    CLog(const char *logfile);
    ~CLog();
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
