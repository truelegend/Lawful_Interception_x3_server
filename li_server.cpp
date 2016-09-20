#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include "li_server.h"
using namespace std;

#define RECV_BUFFER_MAX 4096

CX3parser *g_pX3parserforUdp = NULL;
CX3parser *g_pX3parserforTcp = NULL;
unsigned int g_udp_recv_num = 0;
unsigned int g_tcp_recv_num = 0;
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
    char buffer[RECV_BUFFER_MAX+1];
    //CX3parser x3parser;
    
    socklen_t len = sizeof(client_addr);
    while(1)
    {
        memset(&buffer,0,sizeof(buffer));
        
        int recv_len = recvfrom(sockfd,buffer,sizeof(buffer),0, (struct sockaddr *)&client_addr,&len);
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
    //unsigned int 
    LOG(DEBUG,"accepted from peer, ip: %s, port: %d", inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
    char buffer[RECV_BUFFER_MAX+1];
    //CX3parser x3parser;
    if (!g_pX3parserforTcp)
    {
         g_pX3parserforTcp = new CX3parser();
    }   
    while(1)
    {
        memset(&buffer,0,sizeof(buffer));
        
    	int recv_len = recv(client_sockfd,buffer,sizeof(buffer),0);
        if (recv_len > 0)
        {
            g_tcp_recv_num++;
    	    LOG(DEBUG,"%d bytes received",recv_len);
            bool parse_ret = g_pX3parserforTcp->parse_x3(buffer,recv_len);
            if (parse_ret == false)
            {
                LOG(ERROR,"failed to parse this x3 pkg, pls check the X3 msg manually, the program is exiting!");
                //exit(1);
            }            
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

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		LOG(ERROR,"wrong arguments number");
        Usage(argv);
		exit(1);
	}
    struct sockaddr_in serv_addr;
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);

    pthread_t udpx3thNo, tcpx3thNo;
    int ret;
    ret = pthread_create(&udpx3thNo,NULL,udpx3thread,&serv_addr);     
    if (ret)                                                                                                                                         
    {                                                                                                                                                
        LOG(ERROR,"failed to create thread, error No. is %d", ret);                                                                        
        exit(1);                                                                                                                                     
    } 
    ret = pthread_create(&tcpx3thNo,NULL,tcpx3thread,&serv_addr);     
    if (ret)                                                                                                                                         
    {                                                                                                                                                
        LOG(ERROR,"failed to create thread, error No. is %d", ret);                                                                        
        exit(1);                                                                                                                                     
    } 
    getchar();      
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
