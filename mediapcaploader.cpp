#include "mediapcaploader.h"
using namespace std;
CMediaPcapLoader* CMediaPcapLoader::instance = NULL;
CMediaPcapLoader::CGarbo CMediaPcapLoader::m_garbo;
CMediaPcapLoader::CMediaPcapLoader()
{
    m_fp = NULL;
    m_rtp_num_frompcap = 0;
    m_rtcp_num_frompcap = 0;
}
CMediaPcapLoader::~CMediaPcapLoader()
{
/*    for(int i=0; i<65536;i++)
    {
        delete [] rtp_table[i].pIP;
    }*/
}
CMediaPcapLoader* CMediaPcapLoader::GetInstance()
{
    if (!instance)
    {
        instance = new CMediaPcapLoader();
    }
    return instance;
}
bool CMediaPcapLoader::LoadPcapfile(const char* pcapfile)
{
    printf("loading pcap file......\n");
    char errbuf[50];
    if ((m_fp = pcap_open_offline(pcapfile, errbuf)) == NULL)
    {
        printf("unable to open pcap file\n");
	return false;
    }
    pcap_loop(m_fp, 0, CMediaPcapLoader::dispatcher_handler, (u_char *)this);
    pcap_close(m_fp);
    printf("loading pcap file done\n");
    return true;
}

void CMediaPcapLoader::dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    assert(temp1 != NULL);  
    CMediaPcapLoader *pLoader = (CMediaPcapLoader *)temp1;
    if(header->caplen != header->len)
    {
        printf("this captured pkg length is not equal with the actual real pkg length!\n");
	return;
    }
    u_short port = ntohs(*(u_short*) (pkt_data+14+20));
    const u_char *rtp_data = pkt_data + 14 + 20 +8;
    int len = header->len - (14 + 20 +8);
    if(port%2 == 0)
    {
	//printf("this is rtp\n");
	pLoader->BuildRtpTable(rtp_data,len);
    }
    else
    {
	//printf("this is rtcp\n");
	pLoader->BuildRtcpQueue(rtp_data,len);

    }
}

void CMediaPcapLoader::BuildRtcpQueue(const u_char *data,int len)
{
    IP_MEDIA_INFO rtcp_info;
    rtcp_info.pApp = new u_char[len];
    if(NULL == rtcp_info.pApp)
    {
        printf("failed to allocate memory for rtcp"); 
	exit(1);
    }
    rtcp_info.len = len;
    memcpy(rtcp_info.pApp,data,len);
    rtcp_queue.push(rtcp_info);   
    m_rtcp_num_frompcap++;
}

void CMediaPcapLoader::BuildRtpTable(const u_char *data,int len)
{
    u_short seq = ntohs(*((u_short*)(data+2)));
    //printf("rtp sequence is %d\n",seq); 
    if(NULL == rtp_table[seq].pApp)
    {
        rtp_table[seq].pApp = new u_char[len];
        if(NULL == rtp_table[seq].pApp)
        {
            printf("failed to allocate memory for rtp");
	    exit(1);
        }
        memcpy(rtp_table[seq].pApp,data,len);
        rtp_table[seq].len = len;
        m_rtp_num_frompcap++;   
    }
    else
    {
	printf("WARNING: the seq %d has be loaded-----due to duplicated rtp or dtmp end package!!\n");
    }
}

bool CMediaPcapLoader::CompareRtpwithX3(const u_char* x3_payload, unsigned int len, u_short seq,int direction)
{
    assert(x3_payload != NULL && len != 0);
    if(rtp_table[seq].len != len || memcmp(x3_payload,rtp_table[seq].pApp,len) != 0)
    {
	LOG(ERROR,"rtp compareing failed, the x3 payload len of sequence %d is %d:%d",seq,rtp_table[seq].len,len);
	return false; 
    }
    //else
    //{LOG(DEBUG,"........................................................................");}
    direction==1?rtp_table[seq].from=true:rtp_table[seq].to=true;
    return true;
}

bool CMediaPcapLoader::CompareRtcpwithX3(const u_char* x3_payload, unsigned int len,int direction)
{
    assert(x3_payload != NULL && len != 0);
    if(rtcp_queue.empty() == true) 
    {
	 LOG(ERROR,"rtcp queue is empty");
         return false;
    }
    IP_MEDIA_INFO & rtcp_info = rtcp_queue.front();
    assert(rtcp_info.pApp != NULL);
    if(rtcp_info.len != len || memcmp(x3_payload,rtcp_info.pApp,len) != 0)
    {
        LOG(ERROR,"rtcp compareing failed, the x3 payload len is %d:%d",rtcp_info.len,len);
	for(int i=0;i<len;i++)
		printf("%02x",rtcp_info.pApp[i]);
	rtcp_queue.pop();
	return false;
    }
    rtcp_queue.pop();
    return true;
}

void CMediaPcapLoader::OutputStaticsFromPcap()
{
    LOG(DEBUG,"the rtp num from pcap file is %d, rtcp num is %d",m_rtp_num_frompcap,m_rtcp_num_frompcap);
    u_int rtp_num_fromX3_from = 0;
    u_int rtp_num_fromX3_to = 0;
    for(int i=0;i<MAX_RTP_NUM;i++)
    {
        if(rtp_table[i].from == true)
	    rtp_num_fromX3_from++;
        if(rtp_table[i].to == true) 
	    rtp_num_fromX3_to++;
    }
    LOG(DEBUG,"the rtp num from x3 is from_target: %d, to_target: %d",rtp_num_fromX3_from,rtp_num_fromX3_to);
    int size = rtcp_queue.size();
    if(size != 0)
    {
	LOG(ERROR,"the size of RTCP queue is %d, there must be RTCP missing from x3",size);
    }
    else
    {
	LOG(DEBUG,"RTCP packages are all handled successfully");
    }
       
}



