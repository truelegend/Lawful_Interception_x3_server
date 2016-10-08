#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include "li_server.h"
#include "udpx3cachequeue.h"
using namespace std;

#define RECV_BUFFER_MAX 2048

CX3parser *g_pX3parserforUdp = NULL;
CX3parser *g_pX3parserforTcp = NULL;
unsigned int g_udp_recv_num = 0;
unsigned int g_tcp_recv_num = 0;
static const int       TIMEOUT = 5;
int parsethread_exit      = 0;
pthread_t g_udpx3thNo, g_tcpx3thNo;
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

int getContentLen(char* data)
{
    string leftstr = "<" + string("PayloadLength") + ">";
    string rightstr = "</" + string("PayloadLength") + ">";
    char* pleft = strstr(data,leftstr.c_str());
    if (!pleft)
    {
        LOG(DEBUG,"Not complete, cannot find %s",leftstr.c_str());
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

int starupServSocket(struct sockaddr_in &serv_addr,int type)
{
    int sockfd = socket(AF_INET,type,0);
    if(sockfd < 0)
    {
        LOG(ERROR,"socket descriptor is invalid, %d:%s",errno,strerror(errno));
        exit(1);
    }
    int brst = bind(sockfd,(struct sockaddr*)&serv_addr,sizeof(struct sockaddr));
    if(brst == -1)
    {
        LOG(ERROR,"error while binding address.");
        exit(1);
    }
    int rcv_size;
    socklen_t optlen =  sizeof(rcv_size); 
    if(-1 == getsockopt(sockfd,SOL_SOCKET, SO_RCVBUF, &rcv_size, &optlen))
    {
        LOG(ERROR,"failed to get sockopt");
	exit(1);
    }
    printf("the old recv buf size is %d\n",rcv_size);
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
    printf("the new recv buf size is %d\n",rcv_size);
    timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    if(setsockopt(sockfd,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) != 0)
    {
        LOG(ERROR,"failed to set TIMEOUT for receiving socket");
        exit(1);
    }
    //exit(1);
    return sockfd;
}
void * parseCachedX3(void *x3queue)
{
    CUdpX3CacheQueue *pQueue = (CUdpX3CacheQueue *)x3queue;
    if(!g_pX3parserforUdp)
    {
        g_pX3parserforUdp = new CX3parser();
    }
    while(1)
    {
        //lock
        pthread_mutex_lock(&g_mutex);
        UDP_X3 *pX3 = pQueue->DeQueue();
        int len;
        u_char *data;
        if (pX3)
        {
            len = pX3->pkg_len;
            data = pX3->p_pkg;
        }
        // unlock   
        pthread_mutex_unlock(&g_mutex);         
        if (NULL == pX3 && parsethread_exit == 0)
        {
            sleep(0.01);
            continue;
        }
        if (NULL == pX3 && parsethread_exit == 1)
        {
            break;
        }
        bool parse_ret = g_pX3parserforUdp->parse_x3(data,len);
        delete [] data;
        if (parse_ret == false)
        {
            LOG(ERROR,"failed to parse this x3 pkg, pls check the ERROR printing above, the program is exiting!");
            exit(1);
        }      
    }
   LOG(DEBUG,"parsing thead exits");   
}
void* udpx3thread(void *pSocket)
{ 
    int *p_serve_sock = (int *)pSocket;
    struct sockaddr_in client_addr;
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
    while(1)
    {
        memset(&buffer,0,sizeof(buffer));
        int recv_len = recvfrom(*p_serve_sock,buffer,RECV_BUFFER_MAX,0, (struct sockaddr *)&client_addr,&len);
        if (recv_len > 0)
        {
            g_udp_recv_num++;
            //LOG(DEBUG,"%d bytes received from ip:%s, port: %d",recv_len,inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
            // lock
            pthread_mutex_lock(&g_mutex);             
            if(x3cachequeue.EnQueue(buffer,recv_len) == -1)
            {
                LOG(ERROR,"failed to enqueue x3 pkg, this is the %d x3 pkg",g_udp_recv_num);
                exit(1);
            }
            // unlock  
            pthread_mutex_unlock(&g_mutex);
        }
        else
        {
            LOG(DEBUG,"the connection broken or something else wrong");
            //close(*p_serve_sock);
            break;
        }
    }
    parsethread_exit = 1;
    if(pthread_join(parsecachedx3thread,NULL) != 0)
    {
        LOG(ERROR,"the udp thread will wait until the parsing thread exits, but seems it doesn't");
    }

    LOG(DEBUG,"udp thead exits");
}
void* tcpx3thread(void *pSocket)
{  
    int *p_serve_sock = (int *)pSocket;
    struct sockaddr_in client_addr;
    memset(&client_addr,0,sizeof(client_addr));
    if(listen(*p_serve_sock,1) == -1)
    {
    	LOG(ERROR,"socket listening failed, %d:%s",errno,strerror(errno));
    	exit(1);
    }
    socklen_t len = sizeof(client_addr);
    int client_sockfd = accept(*p_serve_sock, (struct sockaddr*)&client_addr, &len);
    if (client_sockfd < 0)
    {
    	LOG(DEBUG,"failed to accept, tcp thread exits ");
	return NULL;
    	//exit(1);
    }
    LOG(DEBUG,"accepted from peer, ip: %s, port: %d", inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
    unsigned char buffer[RECV_BUFFER_MAX+1];
    //char buffer[123];
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
    }  
    memset(&tmp_buffer,0,sizeof(tmp_buffer));
    memset(&x3_buffer,0,sizeof(x3_buffer)); 
    while(1)
    {
        memset(&buffer,0,sizeof(buffer));
    	int recv_len = recv(client_sockfd,buffer,RECV_BUFFER_MAX,0);
        //int recv_len = recv(client_sockfd,buffer,123,0);
        if (recv_len > 0)
        {
            g_tcp_recv_num++;
    	    LOG(DEBUG,"%d bytes received from tcp peer",recv_len);
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
                        LOG(DEBUG,"get content_len: %d", content_len);
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
                LOG(DEBUG,"xmlhdr_len %d, content_len %d", xmlhdr_len,content_len);      
                bool parse_ret = g_pX3parserforTcp->parse_x3(x3_buffer,xmlhdr_len+content_len);
                if (parse_ret == false)
                {
                    LOG(ERROR,"failed to parse this x3 pkg, pls check the X3 msg manually, the program is exiting!");
                    exit(1);
                }  
                int next_x3_len = p - tmp_buffer - (xmlhdr_len+content_len);
                next_x3 = (next_x3_len>0)?true:false;
                if (next_x3)
                {
                    memmove(tmp_buffer,tmp_buffer+xmlhdr_len+content_len,next_x3_len);
                    tmp_buffer[next_x3_len] = '\0';
                    LOG(DEBUG,"the next x3 pkg exists, next_x3_len %d",next_x3_len);
                }
                content_len = -1;
                xmlhdr_len = -1;
                more_body_num = -1;
                p = next_x3?tmp_buffer+next_x3_len:tmp_buffer;
                xmlrear = NULL;
            }while(next_x3);
        }
        else
        {
        	LOG(DEBUG,"the connection broken or something else wrong");
            close(client_sockfd);
            //close(*p_serve_sock);
            break;
        }
    }
    LOG(DEBUG,"tcp thead exits");
}

void OutputStatics(CX3parser *pX3parser)
{
    LOG(DEBUG,"total x3 pkg num: %d, from_target num: %d(rtp %d + rtcp %d + msrp %d) + to_target num: %d (rtp %d + rtcp %d + msrp %d)",
                pX3parser->x3_num,
                pX3parser->from_target_num, pX3parser->from_rtp_num, pX3parser->from_rtcp_num, pX3parser->from_msrp_num,
                pX3parser->to_target_num, pX3parser->to_rtp_num, pX3parser->to_rtcp_num, pX3parser->to_msrp_num);
    //LOG(DEBUG,"target ip: %s",pX3parser->target_ip);
    //LOG(DEBUG,"uag    ip: %s",pX3parser->uag_ip);
        for(vector<PORT_PARI_INFO>::iterator iter = pX3parser->vecPort_pair_info.begin(); iter != pX3parser->vecPort_pair_info.end(); ++iter)
        {
	    if(iter->target_port%2 == 0)
	    {
	         LOG(DEBUG,"RTP info:"); 
		float from_target_loss_rate = iter->GetFromRtpLossRate();
		float to_target_loss_rate = iter->GetToRtpLossRate();
                LOG(DEBUG,"target %s:%d, uag %s:%d, from_target_num: %d, to_target_num: %d, rtp payload type: %d, ssrc from target: 0x%X, ssrc to target: 0x%X, from_target_loss_rate: %.2f%, to_target_loss_rate: %.2f%", 
            pX3parser->target_ip,iter->target_port,pX3parser->uag_ip,iter->uag_port,iter->from_target_num,iter->to_target_num,
            iter->payload_type,iter->ssrc_from_target,iter->ssrc_to_target,from_target_loss_rate,to_target_loss_rate);
	    }
	    else
	    {
                LOG(DEBUG,"RTCP info:"); 
                LOG(DEBUG,"target %s:%d, uag %s:%d, from_target_num: %d, to_target_num: %d", 
            pX3parser->target_ip,iter->target_port,pX3parser->uag_ip,iter->uag_port,iter->from_target_num,iter->to_target_num);
         
	    }
        }
}

void Usage(char **argv)
{
    printf("usage:\n");  
    printf("%s listen_ip_address lister_port\n", argv[0]);
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

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		LOG(ERROR,"wrong arguments number");
        Usage(argv);
		exit(1);
	}
    if (signal(SIGINT,sigint_handler) == SIG_ERR)
    {
        LOG(ERROR,"cannot catch signal");
        exit(1);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
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

    LOG(DEBUG,"=============================================================================================================================");
    if (g_tcp_recv_num)
    {
        LOG(DEBUG,"x3 is over TCP, recv function returns %d times", g_tcp_recv_num);
        OutputStatics(g_pX3parserforTcp);
    }
    if (g_udp_recv_num)
    {
        LOG(DEBUG,"x3 is over UDP, recv function returns %d times", g_udp_recv_num);
        OutputStatics(g_pX3parserforUdp);
    }
    if (g_udp_recv_num == 0 && g_tcp_recv_num == 0)
    {
        LOG(DEBUG,"no X3 msg is received");
    }
    delete g_pX3parserforTcp;
    delete g_pX3parserforUdp;
    LOG(DEBUG,"=============================================================================================================================");
}
