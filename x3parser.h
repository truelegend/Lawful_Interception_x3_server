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
#include <map>
#include <bitset>
#include "log.h"
#include "mediapcaploader.h"
#include "x3statistics.h"
// We can actully use #include <linux/ip.h>
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
struct PSEU_IPv4_HDR
{
    struct in_addr   m_in4addrSourIp;
    struct in_addr   m_in4addrDestIp;
    uint8_t m_zero;
    uint8_t m_ptcl;
    uint16_t m_len;
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
struct PSEU_IPv6_HDR
{
    struct in6_addr   m_in6addrSourIp;
    struct in6_addr   m_in6addrDestIp;
    uint32_t m_len;
    uint32_t m_zero: 24;
    uint32_t m_ptcl: 8;
};
struct UDP_HDR
{
    uint16_t m_usSourPort;
    uint16_t m_usDestPort;
    uint16_t m_usLength;
    uint16_t m_usCheckSum;

};
// we can actually use #include <linux/tcp.h> directly
struct TCP_HDR
{
    uint16_t m_usSourPort;
    uint16_t m_usDestPort;
    uint32_t m_SequNum;
    uint32_t m_AcknowledgeNum;
    // Alert! little endian in one byte!
    uint8_t  m_reserve:4;
    uint8_t  m_len:4;
    uint8_t  m_FIN:1;
    uint8_t  m_SYN:1;
    uint8_t  m_RST:1;
    uint8_t  m_PSH:1;
    uint8_t  m_ACK:1;
    uint8_t  m_URG:1;
    uint8_t  m_ECE:1;
    uint8_t  m_CWR:1;
    uint16_t m_usWindowSize;
    uint16_t m_usCheckSum;
    uint16_t m_usUrgentPointer;

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

struct DTMF_2833
{
    uint8_t event;
    unsigned  volume:6;
    unsigned R:1;
    unsigned E:1;
    uint16_t duration;
};

/*struct PORT_PARI_INFO
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
*/

class CX3parser
{
public:
    CX3parser();
    ~CX3parser();
    bool parse_x3(unsigned char *x3, int x3_len);

    void SetEnableCompare(bool b) {
        m_benableCompare = b;
    }
    void SetIPChecksum(bool b) {
        m_ipchecksum = b;
    }
    void SetIfDumpX3(bool b) {
        m_dumpX3 = b;
    }

    CX3Statistics m_x3statistics;

private:
    typedef bool (*check_ipv4_hdr_func)(IPv4_HDR *hdr);
    typedef bool (*check_ipv6_hdr_func)(IPv6_HDR *hdr); 
    typedef bool (*check_tcp_hdr_func)(TCP_HDR *hdr);
    int sock;
    struct sockaddr_in peeraddr;
    unsigned char *m_x3;
    int m_x3_len;
    char tmp[100];
    int m_payloadlen;
    X3_PAYLOAD_TYPE m_payloadtype;
    int m_calldirection;
    int m_real_rtptype;
    unsigned int m_iptype;

    char m_format_x3[4096];
    bool m_dumpX3;

    unsigned char *m_xmlrear;

    bool m_ipchecksum;

    bool getElementValue(const char* str, char* value);
    bool verifyX3hdrformat();
    char *getX3hdrrear();
    bool parse_x3body(unsigned char *body, int len);
    bool parse_x3body_MSRP(unsigned char *body, int len);
    bool parse_x3body_RTXP(unsigned char *body, int len);
    bool parse_ip_hdr(unsigned char *body, int &ip_hdr_len, int &total_len, uint8_t prot, bool do_checksum, check_ipv4_hdr_func ipv4_checker=NULL, check_ipv6_hdr_func ipv6_checker=NULL);
    bool verifyIPhdrChecksum(u_short *hdr, u_int size);
    bool verifyTCPhdrChecksum(unsigned char *hdr, int size);
    unsigned short parse_udp_hdr(unsigned char *body);
    bool parse_tcp_hdr(unsigned char *body, int total_len, int &hdr_len, check_tcp_hdr_func tcp_checker=NULL);
    bool parse_rtp(unsigned char *data,int rtp_len);
    bool parse_rtcp(unsigned char *data,int rtcp_len);
    bool parse_msrp(unsigned char *data);

    bool IsValidDTMF(u_char *dtmf, int dtmf_len,bool & b_end);
    void formatX3();
    char* formatX3xml();
    void formatX3payload(unsigned char *data);

    void initializeArguments();
    bool setPortPairInfo(unsigned short src_port, unsigned short dst_port);

    void SetMinMaxSeq(int &min,int &max,unsigned short seq);
    static bool check_ipv4_hdr_for_msrp(IPv4_HDR *hdr);
    static bool check_ipv6_hdr_for_msrp(IPv6_HDR *hdr); 
    static bool check_tcp_hdr_for_msrp(TCP_HDR *hdr);
    
    bool m_benableCompare;
    PSEU_IPv4_HDR m_pseu_ipv4_hdr;
    PSEU_IPv6_HDR m_pseu_ipv6_hdr;
    
};
#endif
