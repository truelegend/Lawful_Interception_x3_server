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
using namespace std;

#define RECV_BUFFER_MAX 2048

CX3parser *g_pX3parserforUdp = NULL;
CX3parser *g_pX3parserforTcp = NULL;
unsigned int g_udp_recv_num = 0;
unsigned int g_tcp_recv_num = 0;

pthread_t g_udpx3thNo, g_tcpx3thNo;

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

void* udpx3thread(void *addr)
{ 
    struct sockaddr_in *p_serv_addr = (struct sockaddr_in *)addr;
    int sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if(sockfd < 0)
    {
        LOG(ERROR,"socket descriptor is invalid, %d:%s",errno,strerror(errno));
        exit(1);
    }
    struct sockaddr_in client_addr;
    memset(&client_addr,0,sizeof(client_addr));
    int brst = bind(sockfd,(struct sockaddr*)p_serv_addr,sizeof(struct sockaddr));
    if(brst == -1)
    {
        LOG(ERROR,"error while binding address.");
        exit(1);
    }
    unsigned char buffer[RECV_BUFFER_MAX+1];
    //CX3parser x3parser;
    
    socklen_t len = sizeof(client_addr);
    while(1)
    {
        memset(&buffer,0,sizeof(buffer));
        
        int recv_len = recvfrom(sockfd,buffer,RECV_BUFFER_MAX,0, (struct sockaddr *)&client_addr,&len);
        if (recv_len > 0)
        {
            g_udp_recv_num++;
            LOG(DEBUG,"%d bytes received from ip:%s, port: %d",recv_len,inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
            if(!g_pX3parserforUdp)
            {
                g_pX3parserforUdp = new CX3parser();
            }            
            bool parse_ret = g_pX3parserforUdp->parse_x3(buffer,recv_len);
            if (parse_ret == false)
            {
                LOG(ERROR,"failed to parse this x3 pkg, pls check the ERROR printing above, the program is exiting!");
                close(sockfd);
                exit(1);
            }            
        }
        else
        {
            LOG(DEBUG,"the tcp connection broken or something else wrong");
            close(sockfd);
            break;
        }
    }
    LOG(DEBUG,"thead exits");
}
void* tcpx3thread(void *addr)
{   
    struct sockaddr_in *p_serv_addr = (struct sockaddr_in *)addr;
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd < 0)
    {
        LOG(ERROR,"socket descriptor is invalid, %d:%s",errno,strerror(errno));
        exit(1);
    }
    struct sockaddr_in client_addr;
    memset(&client_addr,0,sizeof(client_addr));
    int brst = bind(sockfd,(struct sockaddr*)p_serv_addr,sizeof(struct sockaddr));
    if(brst == -1)
    {
        LOG(ERROR,"error while binding address.");
        exit(1);
    }
    if(listen(sockfd,1) == -1)
    {
    	LOG(ERROR,"socket listening failed, %d:%s",errno,strerror(errno));
    	exit(1);
    }
    socklen_t len = sizeof(client_addr);
    int client_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
    if (client_sockfd < 0)
    {
    	LOG(ERROR,"failed to accept ");
    	exit(1);
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
            close(sockfd);
            break;
        }
    }
    LOG(DEBUG,"thead exits");
}
void OutputStatics(CX3parser *pX3parser)
{
    LOG(DEBUG,"total x3 pkg num: %d, from_target num: %d(rtp %d + rtcp %d + msrp %d) + to_target num: %d (rtp %d + rtcp %d + msrp %d)",
                pX3parser->x3_num,
                pX3parser->from_target_num, pX3parser->from_rtp_num, pX3parser->from_rtcp_num, pX3parser->from_msrp_num,
                pX3parser->to_target_num, pX3parser->to_rtp_num, pX3parser->to_rtcp_num, pX3parser->to_msrp_num);
    //LOG(DEBUG,"target ip: %s",pX3parser->target_ip);
    //LOG(DEBUG,"uag    ip: %s",pX3parser->uag_ip);
    if (pX3parser->vecPort_pair_info.size() != 0)
    {
        LOG(DEBUG,"the detailed RTP/RTCP info: ");
        for(vector<PORT_PARI_INFO>::iterator iter = pX3parser->vecPort_pair_info.begin(); iter != pX3parser->vecPort_pair_info.end(); ++iter)
        {
            LOG(DEBUG,"target %s:%d, uag %s:%d, from_target_num: %d, to_target_num: %d", 
            pX3parser->target_ip,(*iter).target_port,pX3parser->uag_ip,(*iter).uag_port,(*iter).from_target_num,(*iter).to_target_num);
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

    int ret;
    ret = pthread_create(&g_udpx3thNo,NULL,udpx3thread,&serv_addr);     
    if (ret)                                                                                                                                         
    {                                                                                                                                                
        LOG(ERROR,"failed to create udp thread, error No. is %d", ret);                                                                        
        exit(1);                                                                                                                                     
    } 
    ret = pthread_create(&g_tcpx3thNo,NULL,tcpx3thread,&serv_addr);     
    if (ret)                                                                                                                                         
    {                                                                                                                                                
        LOG(ERROR,"failed to create tcp thread, error No. is %d", ret);                                                                        
        exit(1);                                                                                                                                     
    } 
    //getchar();      
    if(pthread_join(g_tcpx3thNo,NULL) != 0)
    {
        LOG(ERROR,"the main thread will wait until the receiving thread exits, but seems it doesn't");
    }
    if(pthread_join(g_udpx3thNo,NULL) != 0)
    {
        LOG(ERROR,"the main thread will wait until the receiving thread exits, but seems it doesn't");
    }
    LOG(DEBUG,"=============================================================================================================================");
    if (g_pX3parserforTcp)
    {
        LOG(DEBUG,"x3 is over TCP, recv function returns %d times", g_tcp_recv_num);
        OutputStatics(g_pX3parserforTcp);
    }
    if (g_pX3parserforUdp)
    {
        LOG(DEBUG,"x3 is over UDP, recv function returns %d times", g_udp_recv_num);
        OutputStatics(g_pX3parserforUdp);
    }
    if (!g_pX3parserforTcp && !g_pX3parserforUdp)
    {
        LOG(DEBUG,"no X3 msg is received");
    }
    delete g_pX3parserforTcp;
    delete g_pX3parserforUdp;
    LOG(DEBUG,"=============================================================================================================================");
}
