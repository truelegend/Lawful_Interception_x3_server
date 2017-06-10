#include "log.h"

static const char* log_level_array[] = {"DEBUG","WARNING","ERROR"};
CLog* CLog::instance = NULL;
CLog::CGarbo CLog::m_garbo;
CLog::CLog(const char *logfile)
{
    m_logfile = fopen(logfile, "w");
    if (!m_logfile)
    {
        printf("unable to open log file, exit\n");
        exit(1);
    }
    //mutex_x = PTHREAD_MUTEX_INITIALIZER;
    int ret = pthread_mutex_init(&mutex_x, NULL);
    if (ret != 0)
        printf("error happend when try to initialize mutex\n");
}
CLog::~CLog()
{
    if (m_logfile)
        fclose(m_logfile);
    int ret = pthread_mutex_destroy(&mutex_x);
    if (ret != 0)
        printf("error happend when try to deinitialize mutex\n");
    //if (instance)
    //  delete instance;
}
CLog* CLog::GetInstance(const char* logfile)
{
    if (!instance)
    {
        instance = new CLog(logfile);
    }
    return instance;
}
void CLog::WriteLog(const char* func,const char* codeFile, long codeLine,int level, const char* format,...)
{
    pthread_mutex_lock(&mutex_x);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    char str[20480] = {0};
    va_list args;
    va_start(args, format);
    vsprintf(str, format, args);
    va_end(args);
    //struct timeval time;
    //gettimeofday(&time,NULL);
    time_t tNow;
    time(&tNow);
    tm* tLocalTime = localtime(&tNow);
    char szTime[30] = {'\0'};
    strftime(szTime,30, "%H:%M:%S", tLocalTime);

    printf("<%s %s>[%s(%s:%d)] %s\n", szTime,log_level_array[level],func,codeFile,codeLine,str);
    fprintf(m_logfile, "<%s %s>[%s(%s:%d)] %s\n", szTime,log_level_array[level],func,codeFile,codeLine,str);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_mutex_unlock(&mutex_x);
}

void CLog::WriteRawLog(const char* format,...)
{
    pthread_mutex_lock(&mutex_x);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    char str[20480] = {0};
    va_list args;
    va_start(args, format);
    vsprintf(str, format, args);
    va_end(args);
    printf("%s\n",str);
    fprintf(m_logfile, "%s\n",str);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_mutex_unlock(&mutex_x);
}















































