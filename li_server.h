#ifndef _UTIL_H_LISERVER
#define _UTIL_H_LISERVER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <ctime>
#include <pthread.h>
#include "x3parser.h"
#include "log.h"

int getContentLen(char* data);
char *getXmlRear(char *data);
void sigint_handler(int sig);
int starupServSocket(struct sockaddr_in &serv_addr,int type);
#endif
