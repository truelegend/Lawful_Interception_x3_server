#ifndef _UTIL_H_PCAP_LOADER
#define _UTIL_H_PCAP_LOADER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <ctime>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <queue>
#include "log.h"

#define MAX_RTP_NUM 65536
#define COMPARE_RTP(a,b,c,d) CMediaPcapLoader::GetInstance()->CompareRtpwithX3(a,b,c,d)
#define COMPARE_RTCP(a,b,c) CMediaPcapLoader::GetInstance()->CompareRtcpwithX3(a,b,c)
#define LOAD_PCAP(a) CMediaPcapLoader::GetInstance()->LoadPcapfile(a)
struct IP_MEDIA_INFO
{
    IP_MEDIA_INFO()
    {
        from = false;
	to = false;
	pApp = NULL;
	len = 0;
    }
    IP_MEDIA_INFO(const IP_MEDIA_INFO & d)
    {
        from = d.from;
	to = d.to;
	pApp = new u_char[d.len];
	memcpy(pApp,d.pApp,d.len);
	len = d.len;
    }
   ~IP_MEDIA_INFO()
    {
	//if(pIP)
	{
	    delete[] pApp;
	}
    }
    bool from;
    bool to;
    u_char * pApp;
    unsigned int len;
};
class CMediaPcapLoader
{
public:
    static CMediaPcapLoader* GetInstance();
    bool LoadPcapfile(const char* pcapfile);
    bool CompareRtpwithX3(const u_char* x3_payload,unsigned int len,u_short seq,int direction);
    bool CompareRtcpwithX3(const u_char* x3_payload,unsigned int len,int direction);
    void OutputStaticsFromPcap();

private:
    IP_MEDIA_INFO rtp_table[MAX_RTP_NUM];
    std::queue<IP_MEDIA_INFO> rtcp_queue;
    CMediaPcapLoader();
    ~CMediaPcapLoader();
    pcap_t *m_fp;
    static CMediaPcapLoader* instance;

    static void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
    void BuildRtpTable(const u_char *data,int len);
    void BuildRtcpQueue(const u_char *data,int len);
    u_int m_rtp_num_frompcap;
    u_int m_rtcp_num_frompcap;
};

#endif
