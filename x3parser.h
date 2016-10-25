#ifndef _UTIL_H_X3PARSER
#define _UTIL_H_X3PARSER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <ctime>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <exception>
#include <stdexcept>
#include <vector>
#include <bitset>
#include "log.h"
#include "mediapcaploader.h"
#define IP_STRING_NUM 256
struct IPv4_HDR
{
    uint8_t    m_cVersionAndHeaderLen;
    uint8_t    m_cTypeOfService;
    uint16_t   m_sTotalLenOfPacket;
    uint16_t   m_sPacketID;
    uint16_t   m_sSliceinfo;
    uint8_t    m_cTTL;
    uint8_t    m_cTypeOfProtocol;
    uint16_t   m_sCheckSum;
    struct in_addr   m_in4addrSourIp;
    struct in_addr   m_in4addrDestIp;
    //unsigned int m_uiSourIp;
    //unsigned int m_uiDestIp;
};
struct IPv6_HDR
{
    uint32_t m_version_class_flowlabel;
    uint16_t m_usPayloadlen;
    uint8_t  m_ucNexthdr;
    uint8_t  m_ucHoplimit;
    struct in6_addr   m_in6addrSourIp;
    struct in6_addr   m_in6addrDestIp;
    //unsigned char  m_ucSrcIp[16];
    //unsigned char  m_ucDstIp[16];
};
struct UDP_HDR
{
    uint16_t m_usSourPort;
    uint16_t m_usDestPort;
    uint16_t m_usLength;
    uint16_t m_usCheckSum;

};
struct RTP_HDR
{

    unsigned  cc:4; /* CSRC count */
    unsigned  x:1; /* header extension flag */
    unsigned  p:1; /* padding flag */
    unsigned  v:2; /* packet type */

    unsigned  pt:7; /* payload type */
    unsigned  m:1; /* marker bit */

    uint16_t   seq;      /* sequence number            */
    uint32_t     ts;       /* timestamp                  */
    uint32_t     ssrc;     /* synchronization source     */
};
struct PORT_PARI_INFO
{
    PORT_PARI_INFO(unsigned short t_port,unsigned short u_port,unsigned int from_num,unsigned int to_num)
    {
        target_port     = t_port;
        uag_port        = u_port;
        from_target_num = from_num;
        to_target_num   = to_num;
        payload_type        = -1;
        ssrc_from_target    = 0;
        ssrc_to_target      = 0;
        from_target_minseq  = -1;
        from_target_maxseq  = -1;
        to_target_minseq    = -1;
        to_target_maxseq    = -1;
    }
    float GetFromRtpLossRate()
    {
        return GetRtpLossRate(from_target_seqset.count(),from_target_minseq,from_target_maxseq);
    }
    float GetToRtpLossRate()
    {
        return GetRtpLossRate(to_target_seqset.count(),to_target_minseq,to_target_maxseq);
    }
    float GetRtpLossRate(unsigned int real_sum, int min, int max)
    {
	LOG(DEBUG,"real_sum %d, min seq %d, max seq %d",real_sum,min,max);
        if(real_sum == 0)
            return 0;
        unsigned expected_sum  = (min <= max)?(max-min+1):(65536-min+max+1);
        assert(expected_sum >= real_sum);
        float rate =  (float)(expected_sum - real_sum) / expected_sum * 100;
	//printf("it is: %d, %d, %.6f\n",expected_sum - real_sum,expected_sum,rate);
	return rate;
    }
    unsigned short target_port;
    unsigned short uag_port;
    unsigned int   from_target_num;
    unsigned int   to_target_num;
    std::bitset<65536> from_target_seqset;
    std::bitset<65536> to_target_seqset;
    int            payload_type;
    unsigned int   ssrc_from_target;
    unsigned int   ssrc_to_target;
    int            from_target_minseq;
    int            from_target_maxseq;
    int            to_target_minseq;
    int            to_target_maxseq;
};


class CX3parser
{
public:
    CX3parser();
    ~CX3parser();
    bool parse_x3(unsigned char *x3, int x3_len);
    bool isIpv4type() {
        return (m_iptype==IPV4)?true:false;
    }
    void SetEnableCompare(bool b){m_benableCompare = b;}
    unsigned int x3_num;
    unsigned int from_target_num;
    unsigned int to_target_num;

    unsigned int from_rtp_num;
    unsigned int from_rtcp_num;
    unsigned int from_msrp_num;

    unsigned int to_rtp_num;
    unsigned int to_rtcp_num;
    unsigned int to_msrp_num;

    char *target_ip;
    char *uag_ip;
    std::vector<PORT_PARI_INFO> vecPort_pair_info;

private:
    enum PayloadType
    {
        RTP =    0,
        MSRP =   1,
        NOTYPE = 2
    };
    enum CallDirection
    {
        TOTARGET   =  0,
        FROMTARGET =  1,
        NODIRECTION =  2
    };
    enum RTPTYPE
    {
        REAL_RTP  = 0,
        REAL_RTCP = 1,
        REAL_NO   = 2
    };
    enum IPTYPE
    {
        IPV4 = 4,
        IPV6 = 6,
        NOIP = 2
    };
    int sock;
    struct sockaddr_in peeraddr;
    unsigned char *m_x3;
    int m_x3_len;
    char tmp[100];
    int m_payloadlen;
    int m_payloadtype;
    int m_calldirection;
    int m_real_rtptype;
    int m_iptype;

    char m_format_x3[4096];
    unsigned char *m_xmlrear;
    std::vector<PORT_PARI_INFO>::iterator m_cur_iter;

    bool getElementValue(const char* str, char* value);
    bool verifyX3hdrformat();
    char *getX3hdrrear();
    bool parse_x3body(unsigned char *body, int len);
    bool parse_ip_hdr(unsigned char *body, int &ip_hdr_len, int &total_len);
    unsigned short parse_udp_hdr(unsigned char *body);
    bool parse_rtp(unsigned char *data,int rtp_len);
    bool parse_rtcp(unsigned char *data,int rtcp_len);
    bool parse_msrp(unsigned char *data);
    bool getIPaddrAndVerify(void *src, void *dst, int af);
    void formatX3();
    char* formatX3xml();
    void formatX3payload(unsigned char *data);
    //bool setAndVerifyIPtype(int iptype);
    void initializeArguments();
    bool setPortPairInfo(unsigned short src_port, unsigned short dst_port);
    std::vector<PORT_PARI_INFO>::iterator findExistedPortPair(unsigned short target_port,unsigned short uag_port);

    template<typename T1, typename T2,typename T3>
    bool SetAndVerifyValue(T1& argu,const T2 iniValue, const T3 newValue)
    {
        if (argu == iniValue)
        {
            argu = newValue;
        }
        else if (argu != newValue)
        {
            LOG(ERROR,"should be something wrong, the previous is 0x%x, the current is 0x%x",argu, newValue);
            return false;
        }
        return true;
    }
    void SetMinMaxSeq(int &min,int &max,unsigned short seq);
    bool m_benableCompare;
};
#endif
