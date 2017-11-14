#include "log.h"
#include <assert.h>
static const char* log_level_array[] = {"DEBUG","WARNING","ERROR"};
//CLog* CLog::instance = NULL;
CLog* CLog::instance = new CLog();
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
    {
        printf("error happend when try to initialize mutex\n");
	exit(1);
    }
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
CLog* CLog::GetInstance()
{
    if (!instance)
    {
	printf("this should not happen............");
        instance = new CLog();
    }
    return instance;
}
void CLog::WriteLog(const char* func,const char* codeFile, long codeLine,
		int level, const char* format,...)
{
    pthread_mutex_lock(&mutex_x);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    va_list args;
    va_start(args, format);
    int n = vsnprintf(NULL, 0, format, args) + 1;
    assert(n>1);
    va_end(args);
    char str = new char[n];
    assert(str != NULL);
    va_start(args, format);
    vsnprintf(str, n,format, args);
    str[n-1] = '\0';
    va_end(args);
    time_t tNow;
    time(&tNow);
    tm* tLocalTime = localtime(&tNow);
    char szTime[30] = {'\0'};
    strftime(szTime,30, "%H:%M:%S", tLocalTime);

    printf("<%s %s>[%s(%s:%ld)] %s\n", szTime,log_level_array[level],func,codeFile,codeLine,str);
    fprintf(m_logfile, "<%s %s>[%s(%s:%ld)] %s\n", szTime,log_level_array[level],func,codeFile,codeLine,str);
    delete[] str;
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

void CLog::SpecifyLogfilename(const char *logfilename)
{
    pthread_mutex_lock(&mutex_x);
    if(m_logfile)
    {
	fclose(m_logfile);
	m_logfile = NULL;
    }
    m_logfile = fopen(logfilename, "w");
    if (!m_logfile)
    {
	printf("unable to open log file, exit\n");
	exit(1);
    }
    pthread_mutex_unlock(&mutex_x);
}

