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

#define IP_STRING_NUM 256
struct IPv4_HDR
{
    unsigned char    m_cVersionAndHeaderLen;
    unsigned char    m_cTypeOfService;
    unsigned short   m_sTotalLenOfPacket;
    unsigned short   m_sPacketID;
    unsigned short   m_sSliceinfo;
    unsigned char    m_cTTL;
    unsigned char    m_cTypeOfProtocol;
    unsigned short   m_sCheckSum;
    struct in_addr   m_in4addrSourIp;
    struct in_addr   m_in4addrDestIp;
    //unsigned int m_uiSourIp;
    //unsigned int m_uiDestIp;
};
struct IPv6_HDR
{
    unsigned int m_version_class_flowlabel;
    unsigned short m_usPayloadlen;
    unsigned char  m_ucNexthdr;
    unsigned char  m_ucHoplimit;
    struct in6_addr   m_in6addrSourIp;
    struct in6_addr   m_in6addrDestIp;
    //unsigned char  m_ucSrcIp[16];
    //unsigned char  m_ucDstIp[16];
};
struct UDP_HDR
{
    unsigned short m_usSourPort;
    unsigned short m_usDestPort;
    unsigned short m_usLength;  
    unsigned short m_usCheckSum;  
    
};
struct RTP_HDR
{
             
    unsigned  cc:4; /* CSRC count */
    unsigned  x:1; /* header extension flag */
    unsigned  p:1; /* padding flag */
    unsigned  v:2; /* packet type */

    unsigned  pt:7; /* payload type */
    unsigned  m:1; /* marker bit */
    
    unsigned short   seq;      /* sequence number            */  
    unsigned int     ts;       /* timestamp                  */  
    unsigned int     ssrc;     /* synchronization source     */  
};
struct PORT_PARI_INFO
{
    unsigned short target_port;
    unsigned short uag_port;
    unsigned int from_target_num;
    unsigned int to_target_num;
};


class CX3parser
{
public:
    CX3parser();
    ~CX3parser();
    bool parse_x3(unsigned char *x3, int x3_len);
    bool isIpv4type(){ return (m_iptype==IPV4)?true:false; }

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
    
    bool getElementValue(const char* str, char* value);
    bool verifyX3hdrformat();
    char *getX3hdrrear();
    bool parse_x3body(unsigned char *body, int len);
    bool parse_ip_hdr(unsigned char *body, int &ip_hdr_len, int &total_len);
    unsigned short parse_udp_hdr(unsigned char *body);
    bool parse_rtp(unsigned char *data,int rtp_len);
    void parse_msrp(unsigned char *data);
    bool getIPaddrAndVerify(void *src, void *dst, int af);
    void formatX3();
    char* formatX3xml();
    void formatX3payload(unsigned char *data);
    bool setAndVerifyIPtype(int iptype);
    void initializeArguments();
    bool setPortPairInfo(unsigned short src_port, unsigned short dst_port);
    std::vector<PORT_PARI_INFO>::iterator findExistedPortPair(unsigned short target_port,unsigned short uag_port);

};
#endif
