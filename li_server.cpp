#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include "li_server.h"
#include "udpx3cachequeue.h"
#include <net/if.h>
using namespace std;

#define RECV_BUFFER_MAX 2048

CX3parser *g_pX3parserforUdp = NULL;
CX3parser *g_pX3parserforTcp = NULL;
unsigned int g_udp_recv_num = 0;
unsigned int g_tcp_recv_num = 0;
unsigned int       TIMEOUT = 60;
unsigned int       timeout = 2;
bool               gIP_CHECKSUM = false;
bool g_benablePcapFile = false;
bool g_bdumpX3         = false;
int parsethread_exit      = 0;
pthread_t g_udpx3thNo, g_tcpx3thNo;
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
int getContentLen(char* data)
{
    string leftstr = "<" + string("PayloadLength") + ">";
    string rightstr = "</" + string("PayloadLength") + ">";
    char* pleft = strstr(data,leftstr.c_str());
    if (!pleft)
    {
        //LOG(DEBUG,"Not complete, cannot find %s",leftstr.c_str());
        return -1;
    }
    char* pright = strstr(data,rightstr.c_str());
    if (!pright)
    {
        LOG(DEBUG,"Not complete cannot to find %s",rightstr.c_str());
        return -1;
    }
    int len = leftstr.size();
    pleft += len;
    char value[10];
    memcpy(value,pleft,pright-pleft);
    value[pright-pleft] = '\0';
    return atoi(value);
}

char *getXmlRear(char *data)
{
    char* rear = strstr(data,"</hi3-uag>");
    if (!rear)
    {
        LOG(DEBUG,"Not complete, cannot find </hi3-uag>");
        return NULL;
    }
    return (rear+strlen("</hi3-uag>"));
}

int starupServSocket(struct sockaddr_in6 &serv_addr,int type)
{
    int sockfd = socket(AF_INET6,type,0);
    if(sockfd < 0)
    {
        LOG(ERROR,"socket descriptor is invalid, error code: %d-%s",errno,strerror(errno));
        exit(1);
    }
    //By default, /proc/sys/net/ipv6/bindv6only would be 0, i.e. IPV6_V6ONLY is off. Add the logic below in case 
    //the bindv6only value is changed manually. This setsockopt func should be called before bind() 
    int no = 0;     
    if(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&no, sizeof(no)) != 0)
    {
        LOG(ERROR,"failed to disable ipv6only mode, %d:%s",errno,strerror(errno));
	exit(1);
    }
    int brst = bind(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr));
    if(brst == -1)
    {
        LOG(ERROR,"failed to bind address, error code: %d-%s",errno,strerror(errno));
        exit(1);
    }
    int rcv_size;
    socklen_t optlen =  sizeof(rcv_size);
    if(-1 == getsockopt(sockfd,SOL_SOCKET, SO_RCVBUF, &rcv_size, &optlen))
    {
        LOG(ERROR,"failed to get sockopt");
        exit(1);
    }
    //LOG(DEBUG,"the old recv buf size is %d",rcv_size);
    //exit(1);

    int nRecvBuf=1024*1024*10;
    if(-1 == setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,(const char*)&nRecvBuf,sizeof(int)))
    {
        LOG(ERROR,"failed to set sockopt");
        exit(1);
    }

    optlen =  sizeof(rcv_size);
    if(-1 == getsockopt(sockfd,SOL_SOCKET, SO_RCVBUF, &rcv_size, &optlen))
    {
        LOG(ERROR,"failed to get sockopt");
        exit(1);
    }
    //LOG(DEBUG,"the new recv buf size is %d",rcv_size);
    timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    if(setsockopt(sockfd,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) != 0)
    {
        LOG(ERROR,"failed to set TIMEOUT for receiving socket");
        exit(1);
    }
    
    return sockfd;
}
char * TransIPv4MappedAddr(char *src)
{
    const char *prefix = "::ffff:";
    int pre_len = strlen(prefix);
    if(strncmp(src,prefix,pre_len) == 0) 
    {
	LOG(DEBUG,"X3 is from the IPv4 address");
	return src+pre_len;
    }
    else
    {
	LOG(DEBUG,"X3 is from the IPv6 address");
	return src;
    }
}
void * parseCachedX3(void *x3queue)
{
    CUdpX3CacheQueue *pQueue = (CUdpX3CacheQueue *)x3queue;
    if(!g_pX3parserforUdp)
    {
        g_pX3parserforUdp = new CX3parser();
        g_pX3parserforUdp->SetEnableCompare(g_benablePcapFile);
        g_pX3parserforUdp->SetIPChecksum(gIP_CHECKSUM);
        g_pX3parserforUdp->SetIfDumpX3(g_bdumpX3);
    }
    while(1)
    {
        //lock
        pthread_mutex_lock(&g_mutex);
        UDP_X3 *pX3;
        while((pX3 = pQueue->DeQueue()) == NULL && parsethread_exit == 0)
        {
            pthread_cond_wait(&g_cond, &g_mutex);
        }
        int len;
        u_char *data;
        if (pX3)
        {
            len = pX3->pkg_len;
            data = pX3->p_pkg;
        }
        // unlock
        pthread_mutex_unlock(&g_mutex);
        if (NULL == pX3 && parsethread_exit == 1)
        {
            break;
        }
        bool parse_ret = g_pX3parserforUdp->parse_x3(data,len);
        delete [] data;
        if (parse_ret == false)
        {
            LOG(ERROR,"failed to parse this x3 pkg, pls check the ERROR printing above!");
            //exit(1);
        }
    }
    LOG(DEBUG,"parsing thread exits");
    return NULL;
}
void* udpx3thread(void *pSocket)
{
    int *p_serve_sock = (int *)pSocket;
    struct sockaddr_in6 client_addr;
    memset(&client_addr,0,sizeof(client_addr));
    unsigned char buffer[RECV_BUFFER_MAX+1];
    CUdpX3CacheQueue x3cachequeue;
    pthread_t parsecachedx3thread;
    int ret;
    if ((ret = pthread_create(&parsecachedx3thread,NULL,parseCachedX3,&x3cachequeue)) != 0)
    {
        LOG(ERROR,"failed to create parsing cached x3 thread, error No. is %d", ret);
        exit(1);
    }
    socklen_t len = sizeof(client_addr);
    timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    char strPeerAddr[INET6_ADDRSTRLEN];
    while(1)
    {
        memset(&buffer,0,sizeof(buffer));
        int recv_len = recvfrom(*p_serve_sock,buffer,RECV_BUFFER_MAX,0, (struct sockaddr *)&client_addr,&len);
        if (recv_len > 0)
        {
            g_udp_recv_num++;
            if(g_udp_recv_num == 1)
            {
                if(setsockopt(*p_serve_sock,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) != 0)
                {
                    LOG(ERROR,"failed to set TIMEOUT for receiving socket");
                    exit(1);
                }
		
		getpeername(*p_serve_sock, (struct sockaddr *)&client_addr, &len);
		if(inet_ntop(AF_INET6, &client_addr.sin6_addr, strPeerAddr, sizeof(strPeerAddr)))
		{
		    LOG(DEBUG,"the peer address is: %s, peer port is: %d", TransIPv4MappedAddr(strPeerAddr), ntohs(client_addr.sin6_port));
		}
            }
            //LOG(DEBUG,"%d bytes received from ip:%s, port: %d",recv_len,inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
            // lock
            pthread_mutex_lock(&g_mutex);
            if(x3cachequeue.EnQueue(buffer,recv_len) == -1)
            {
                LOG(ERROR,"failed to enqueue x3 pkg, this is the %d x3 pkg",g_udp_recv_num);
                exit(1);
            }
            pthread_cond_signal(&g_cond);
            // unlock
            pthread_mutex_unlock(&g_mutex);
        }
        else
        {
            LOG(DEBUG,"recvfrom funtion return <= 0");
            //close(*p_serve_sock);
            break;
        }
    }
    // For scenario there no pkg is reveived at at all
    parsethread_exit = 1;
    pthread_cond_signal(&g_cond);
    if(pthread_join(parsecachedx3thread,NULL) != 0)
    {
        LOG(ERROR,"the udp thread will wait until the parsing thread exits, but seems it doesn't");
    }
    pthread_cancel(g_tcpx3thNo);
    LOG(DEBUG,"udp thread exits");
    return NULL;
}
void* tcpx3thread(void *pSocket)
{
    int *p_serve_sock = (int *)pSocket;
    struct sockaddr_in6 client_addr;
    memset(&client_addr,0,sizeof(client_addr));
    if(listen(*p_serve_sock,1) == -1)
    {
        LOG(ERROR,"socket listening failed, %d:%s",errno,strerror(errno));
        exit(1);
    }
    socklen_t len = sizeof(client_addr);
    int client_sockfd = accept(*p_serve_sock, NULL, NULL);
    if (client_sockfd < 0)
    {
        LOG(DEBUG,"failed to accept, tcp thread exits ");
        return NULL;
        //exit(1);
    }
    //LOG(DEBUG,"accepted from peer, ip: %s, port: %d", inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
    getpeername(client_sockfd, (struct sockaddr *)&client_addr, &len);
    char strPeerAddr[INET6_ADDRSTRLEN];
    if(inet_ntop(AF_INET6, &client_addr.sin6_addr, strPeerAddr, sizeof(strPeerAddr)))
    {
        LOG(DEBUG,"the peer address is: %s, peer port is: %d", TransIPv4MappedAddr(strPeerAddr), ntohs(client_addr.sin6_port));
    }
    unsigned char buffer[RECV_BUFFER_MAX+1];
    int content_len = -1;
    int xmlhdr_len = -1;
    bool next_x3 = false;
    int more_body_num = -1;
    unsigned char tmp_buffer[2*RECV_BUFFER_MAX+1];
    unsigned char x3_buffer[RECV_BUFFER_MAX+1];
    unsigned char *p = tmp_buffer;
    unsigned char *xmlrear = NULL;

    if (!g_pX3parserforTcp)
    {
        g_pX3parserforTcp = new CX3parser();
        g_pX3parserforTcp->SetEnableCompare(g_benablePcapFile);
        g_pX3parserforTcp->SetIPChecksum(gIP_CHECKSUM);
        g_pX3parserforTcp->SetIfDumpX3(g_bdumpX3);
    }
    memset(&tmp_buffer,0,sizeof(tmp_buffer));
    memset(&x3_buffer,0,sizeof(x3_buffer));
    timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    while(1)
    {
        memset(&buffer,0,sizeof(buffer));
        int recv_len = recv(client_sockfd,buffer,RECV_BUFFER_MAX,0);
        //int recv_len = recv(client_sockfd,buffer,123,0);
        if (recv_len > 0)
        {
            g_tcp_recv_num++;
            if(g_tcp_recv_num == 1)
            {
                if(setsockopt(client_sockfd,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) != 0)
                {
                    LOG(ERROR,"failed to set TIMEOUT for receiving socket");
                    exit(1);
                }
            }
            //LOG(DEBUG,"%d bytes received from tcp peer",recv_len);
            memcpy(p,buffer,recv_len);
            p += recv_len;
            if((p - tmp_buffer) > sizeof(tmp_buffer))
            {
                LOG(ERROR,"seems not valid x3 msg, out of array");
                exit(1);
            }
            *p = '\0';
            do
            {
                if(more_body_num == -1)
                {
                    if(content_len == -1)
                    {
                        content_len = getContentLen((char *)tmp_buffer);
                        //LOG(DEBUG,"get content_len: %d", content_len);
                        if(content_len == -1)
                        {
                            LOG(DEBUG,"Note: cannot find content_len, need to recv again!");
                            break;
                        }
                    }
                    xmlrear = (unsigned char*)getXmlRear((char *)tmp_buffer);
                    if (NULL == xmlrear)
                    {
                        LOG(DEBUG,"Note: cannot find xml rear, need to recv again!");
                        break;
                    }
                    xmlhdr_len = xmlrear - tmp_buffer;
                    int buf_left_len = p - xmlrear;
                    assert(buf_left_len >= 0);
                    if(content_len > buf_left_len)
                    {
                        more_body_num = content_len - buf_left_len;
                        LOG(DEBUG,"Note: need more body_num from recv: %d, need to recv again!",more_body_num);
                        break;
                    }
                }
                else
                {
                    if(recv_len < more_body_num)
                    {
                        more_body_num -= recv_len;
                        LOG(DEBUG,"Note: still need more body_num from recv: %d, need to recv again!",more_body_num);
                        break;
                    }
                }
                memcpy(x3_buffer,tmp_buffer,xmlhdr_len+content_len);
                //LOG(DEBUG,"xmlhdr_len %d, content_len %d", xmlhdr_len,content_len);
                bool parse_ret = g_pX3parserforTcp->parse_x3(x3_buffer,xmlhdr_len+content_len);
                if (parse_ret == false)
                {
                    LOG(ERROR,"failed to parse this x3 pkg, pls check the X3 msg manually");
                    //exit(1);
                }
                int next_x3_len = p - tmp_buffer - (xmlhdr_len+content_len);
                next_x3 = (next_x3_len>0)?true:false;
                if (next_x3)
                {
                    memmove(tmp_buffer,tmp_buffer+xmlhdr_len+content_len,next_x3_len);
                    tmp_buffer[next_x3_len] = '\0';
                    //LOG(DEBUG,"the next x3 pkg exists, next_x3_len %d",next_x3_len);
                }
                content_len = -1;
                xmlhdr_len = -1;
                more_body_num = -1;
                p = next_x3?tmp_buffer+next_x3_len:tmp_buffer;
                xmlrear = NULL;
            } while(next_x3);
        }
        else
        {
            LOG(DEBUG,"recv funtion return <= 0");
            close(client_sockfd);
            //close(*p_serve_sock);
            break;
        }
    }
    pthread_cancel(g_udpx3thNo);
    LOG(DEBUG,"tcp thead exits");
    return NULL;
}

void OutputStatics(CX3parser *pX3parser)
{
    pX3parser->m_x3statistics.OutputStatics();

    if(g_benablePcapFile == true)
    {
        LOG(DEBUG,"######since the original pcap file is supplied, output the statics:######");
        CMediaPcapLoader::GetInstance()->OutputStaticsFromPcap();
    }
}

void Usage(char **argv)
{
    printf("usage:\n\n%s -l local_port [optional options]\n\n", argv[0]);
    printf("    -l : mandatory arguments, specify the local port for listening x3, this tool will listen on all the local IP addresses\n\n"
           "    -T : timeout timer for socket recv if no pkg is received at all, in seconds, the default is 60s\n\n"
           "    -t : timeout timer for socket recv if x3 pkg has been received, in seconds, the default is 2s\n\n"
           "    -w : specify the outputed log file path and file name, the default is /tmp/li.log\n\n"
           "    -f : specify the original pcap file to be compared with received x3\n\n"
           "    -c : enable the IPv4 hdr checksum\n\n"
           "    -d : dump the x3 msg body\n\n"
          );

    printf("Example:\n\n    ./li_server -l 20000 -d\n\n"
           "    or\n\n"
           "    ./li_server -l 20000 -d -c -T 10 -w /root/my-li.log -f /root/srtp/rtp-rtcp.pcap\n\n"
          );
}

void sigint_handler(int sig)
{
    if (sig == SIGINT)
    {
        LOG(DEBUG,"receiving SIGINT signal");
        if((ESRCH != pthread_kill(g_udpx3thNo,0))
                && (0 != pthread_cancel(g_udpx3thNo)))
        {
            LOG(ERROR,"failed to cancel udp thread");
        }
        if((ESRCH != pthread_kill(g_tcpx3thNo,0))
                && (0 != pthread_cancel(g_tcpx3thNo)))
        {
            LOG(ERROR,"failed to cancel tcp thread");
        }
    }
}

bool parseIPPort(const char *optarg, char *str_ip, char *str_port)
{
    assert(optarg != NULL);
    const char *pc = strchr(optarg,':');
    if(NULL == pc || pc == optarg)
    {
        printf("missing ':' between ip and port");
        return false;
    }
    assert(*(pc+1) != '\0');

    memcpy(str_ip,optarg,pc-optarg);
    str_ip[pc-optarg] = '\0';
    strcpy(str_port,pc+1);
    return true;
}

int main(int argc, char **argv)
{
    unsigned short server_port = 0;
    const char *argus = "l:f:t:T:w:hcd";
    int opt;
    while ((opt = getopt(argc, argv, argus)) != -1)
    {
        switch(opt)
        {
        case 'f':
            g_benablePcapFile = true;
            if(LOAD_PCAP(optarg) == false)
            {
                printf("failed to load pcap file, exit\n");
                exit(1);
            }
            break;
        case 'd':
            //printf("will dump the x3 message\n");
            g_bdumpX3 = true;
            break;
        case 'l':
            /*if((b_getAddr = parseIPPort(optarg,str_ip,str_port)) == false)
            {
                Usage(argv);
                exit(1);
            }*/
	    server_port = atoi(optarg);
            break;
        case 'T':
            TIMEOUT = atoi(optarg);
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'c':
            printf("enable IPv4 header checksum\n");
            gIP_CHECKSUM = true;
            break;
        case 'w':
            if(CLog::GetInstance(optarg) == NULL)
            {
                printf("failed to get the instance of log class, exit\n");
                exit(1);
            }
            break;
        case 'h':
        case ':':
        case '?':
            Usage(argv);
            exit(1);
            break;
        default:
            break;
        }
    }
    if(0 == server_port)
    {
	printf("\nError: you should at least specify the port with -l\n\n");
        Usage(argv);
	exit(1);
    }
    // This is important to initialize Log instance firstly to avoid initialization in multiple-thread
    LOG(DEBUG,"Li X3 server is launching...");
    if (signal(SIGINT,sigint_handler) == SIG_ERR)
    {
        LOG(ERROR,"cannot catch signal");
        exit(1);
    }
    struct sockaddr_in6 serv_addr;
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_port = htons(server_port);
    serv_addr.sin6_addr = in6addr_any;
    //serv_addr.sin6_scope_id = if_nametoindex("lo");
    int udp_socket = starupServSocket(serv_addr,SOCK_DGRAM);
    int tcp_socket = starupServSocket(serv_addr,SOCK_STREAM);
    int ret;
    if ((ret = pthread_create(&g_udpx3thNo,NULL,udpx3thread,&udp_socket)) != 0)
    {
        LOG(ERROR,"failed to create udp thread, error No. is %d", ret);
        exit(1);
    }
    if ((ret = pthread_create(&g_tcpx3thNo,NULL,tcpx3thread,&tcp_socket)) != 0)
    {
        LOG(ERROR,"failed to create tcp thread, error No. is %d", ret);
        exit(1);
    }

    if(pthread_join(g_tcpx3thNo,NULL) != 0)
    {
        LOG(ERROR,"the main thread will wait until the receiving thread exits, but seems it doesn't");
    }
    if(pthread_join(g_udpx3thNo,NULL) != 0)
    {
        LOG(ERROR,"the main thread will wait until the receiving thread exits, but seems it doesn't");
    }
    close(udp_socket);
    close(tcp_socket);

    LOG_RAW("=========================================================================================");
    if (g_tcp_recv_num)
    {
        LOG_RAW("x3 is over TCP");//, recv function returns %d times", g_tcp_recv_num);
        OutputStatics(g_pX3parserforTcp);
    }
    if (g_udp_recv_num)
    {
        LOG_RAW("x3 is over UDP");//, recv function returns %d times", g_udp_recv_num);
        OutputStatics(g_pX3parserforUdp);
    }
    if (g_udp_recv_num == 0 && g_tcp_recv_num == 0)
    {
        LOG_RAW("no X3 msg is received");
    }
    delete g_pX3parserforTcp;
    delete g_pX3parserforUdp;
    LOG_RAW("=========================================================================================");
}
