#include "x3parser.h"
#include <errno.h>
using namespace std;

CX3parser::CX3parser()
{
    m_payloadlen = -1;
    m_payloadtype = X3_NOTYPE;
    m_calldirection = NONE_DIRECTION;
    m_real_rtptype = REAL_NO;

    m_xmlrear      = NULL;
    memset(m_format_x3,'\0',sizeof(m_format_x3));

    m_iptype       = NOIP;

    //struct sockaddr_in peeraddr;
    sock = socket(AF_INET,SOCK_DGRAM,0);
    assert(sock != -1);
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(40000);
    peeraddr.sin_addr.s_addr = inet_addr("10.2.1.75");

    m_dumpX3 = false;

    m_ipchecksum = false;
}

CX3parser::~CX3parser()
{

}


bool CX3parser::parse_x3(unsigned char *x3, int x3_len)
{
    if (x3 == NULL || x3_len == 0)
    {
        LOG(ERROR,"wrong parameters");
        return false;
    }

    m_x3 = x3;
    m_x3_len = x3_len;
    m_x3statistics.x3_num++;
    if(m_dumpX3 == true)
    {
	LOG_RAW("\n");
	LOG(DEBUG,"this is the %d x3 package handled",m_x3statistics.x3_num);
    }
    bool ret = verifyX3hdrformat();
    if (ret == false)
    {
        LOG(ERROR,"wrong x3 hdr format");
	m_x3statistics.RecordErroredX3();
    }
    else
    {
        ret = parse_x3body(m_x3+m_x3_len-m_payloadlen,m_payloadlen);
        if(ret == false)
        {
            LOG(ERROR,"faild to decode x3 body");
            m_x3statistics.RecordErroredX3();
        }
    }
    if(m_dumpX3 == true)
    {
        formatX3();
        LOG(DEBUG,"dump the received x3 data:\n%s", m_format_x3);
    }
    return ret;
}
bool CX3parser::getElementValue(const char* str, char* value)
{
    string leftstr = "<" + string(str) + ">";
    string rightstr = "</" + string(str) + ">";
    char* pleft = strstr((char *)m_x3,leftstr.c_str());
    if (!pleft)
    {
        LOG(ERROR,"failed to find %s",leftstr.c_str());
        return false;
    }
    char* pright = strstr((char *)m_x3,rightstr.c_str());
    if (!pright)
    {
        LOG(ERROR,"failed to find %s",rightstr.c_str());
        return false;
    }
    int len = leftstr.size();
    pleft += len;
    memcpy(value,pleft,pright-pleft);
    value[pright-pleft] = '\0';
    return true;
}
bool CX3parser::parse_x3body(unsigned char *body, int len)
{
    assert(m_xmlrear != NULL);
    if (m_xmlrear != body)
    {
        LOG(ERROR,"this should be wrong, the beginning of x3 body is not correct");
        return false;
    }
    //LOG(DEBUG,"Got the correct beginning of x3 body");
    unsigned char *start = body;
    if(m_payloadtype == X3_MSRP)
    {//return true;
        return parse_x3body_MSRP(start, len);
    }
    else //ip/udp/rtp rtcp 
    {
        return parse_x3body_RTXP(start, len);
    }
}
bool CX3parser::parse_x3body_MSRP(unsigned char *body, int len)
{
    unsigned char *start = body;

    int ip_hdr_len, total_len;
    if (parse_ip_hdr(start, ip_hdr_len, total_len, IPPROTO_TCP, true, check_ipv4_hdr_for_msrp, NULL /* no ipv6 flag check for now*/) == false)
    {
        return false;
    }
    if (total_len != m_payloadlen)
    {
        LOG(ERROR,"the decoded payload len %d is not equal with the decalard one %d",total_len,m_payloadlen);
        return false;
    }
    start += ip_hdr_len;
    int tcp_hdr_len;
    if(!parse_tcp_hdr(start, total_len - ip_hdr_len, tcp_hdr_len, check_tcp_hdr_for_msrp))
    {
        LOG(ERROR,"parsing tcp hdr failed");
        return false;
    }
    start += tcp_hdr_len;
    return parse_msrp((unsigned char*)start);
}
bool CX3parser::parse_x3body_RTXP(unsigned char *body, int len)
{
    unsigned char *start = body;

    int ip_hdr_len, total_len;
    if (parse_ip_hdr(start, ip_hdr_len, total_len, IPPROTO_UDP, m_ipchecksum) == false)
    {
        return false;
    }
    if (total_len != m_payloadlen)
    {
        LOG(ERROR,"the decoded payload len %d is not equal with the decalard one %d",total_len,m_payloadlen);
        return false;
    }
    start += ip_hdr_len;
    int udp_hdrbody_len = parse_udp_hdr(start);
    if(udp_hdrbody_len == 0 ||
            udp_hdrbody_len != (total_len - ip_hdr_len))
    {
        LOG(ERROR,"the udp pkg len %d is not right (total_len - ip_hdr_len)", udp_hdrbody_len,total_len,ip_hdr_len);
        return false;
    }
    //LOG(DEBUG,"udp hdr+body len is %d",udp_hdrbody_len);
    start += sizeof(UDP_HDR);
    /*if (m_payloadtype == MSRP)
    {
        parse_msrp((unsigned char*)start);
    }*/
    if (m_real_rtptype == REAL_RTP)
    {
        return parse_rtp((unsigned char*)start, udp_hdrbody_len - sizeof(UDP_HDR));
    }
    else if(m_real_rtptype == REAL_RTCP)
    {
        return parse_rtcp((unsigned char*)start, udp_hdrbody_len - sizeof(UDP_HDR));
    }
    return false;
}
char* CX3parser::getX3hdrrear()
{
    char* rear = strstr((char *)m_x3,"</hi3-uag>");
    if (!rear)
    {
        LOG(ERROR,"failed to find </hi3-uag>");
        return NULL;
    }
    return (rear+strlen("</hi3-uag>"));
}

bool CX3parser::parse_ip_hdr(unsigned char *body, int &ip_hdr_len, int &total_len, uint8_t prot, bool do_checksum, check_ipv4_hdr_func ipv4_checker, check_ipv6_hdr_func ipv6_checker)
{
    m_iptype = *body>>4;
    switch(m_iptype)
    {
    case IPV4:
    case IPV6:
        if (m_x3statistics.VerifyIPType(m_iptype) == false)
        {
            LOG(ERROR,"ip type cannot change!");
            return false;
        }
        break;
    default:
        LOG(ERROR,"unrecoginzied ip type: %d", m_iptype);
        return false;
    }

    char str_src_ip[IP_STRING_LEN], str_dst_ip[IP_STRING_LEN];
    memset(str_src_ip,0,IP_STRING_LEN);
    memset(str_dst_ip,0,IP_STRING_LEN);
    bool ret;
    switch(m_iptype)
    {
    case IPV4:
    {
        IPv4_HDR *pHdr = (IPv4_HDR *)body;
        if (pHdr->m_cTypeOfProtocol != prot) // for RTP/RTCP, it is over UDP; for MSRP, it is over TCP
        {
            LOG(ERROR,"the upper protocol is not expected: %d vs %d", pHdr->m_cTypeOfProtocol, prot);
            return false;
        }
        ip_hdr_len = (pHdr->m_cVersionAndHeaderLen & 0x0f) *4;
        if (ip_hdr_len != sizeof(IPv4_HDR))
        {
            LOG(ERROR,"the decoded ipv4 hdr is not correct");
            return false;
        }
        if (do_checksum == true && verifyIPhdrChecksum((u_short *)pHdr,ip_hdr_len/2) == false)
        {
            LOG(ERROR,"ip hdr checksum failed");
            return false;
        }
        total_len = ntohs(pHdr->m_sTotalLenOfPacket);
        if(ipv4_checker && !ipv4_checker(pHdr)) {return false;}
        ret = m_x3statistics.VerifyIPAddress(&pHdr->m_in4addrSourIp,&pHdr->m_in4addrDestIp,str_src_ip,str_dst_ip);
        
        m_pseu_ipv4_hdr.m_in4addrSourIp = pHdr->m_in4addrSourIp;
        m_pseu_ipv4_hdr.m_in4addrDestIp = pHdr->m_in4addrDestIp;
        m_pseu_ipv4_hdr.m_zero = 0;
        m_pseu_ipv4_hdr.m_ptcl = prot;
        m_pseu_ipv4_hdr.m_len = htons(total_len - ip_hdr_len);
	break;
    }
    case IPV6:
    {
        IPv6_HDR *pHdr = (IPv6_HDR *)body;
        if (pHdr->m_ucNexthdr != prot) // for RTP/RTCP, it is over UDP
        {
            LOG(ERROR,"the upper protocol is not expected: %d vs %d", pHdr->m_ucNexthdr, prot);
            return false;
        }
        // Won't consider extended ipv6 hdr for now
        ip_hdr_len = sizeof(IPv6_HDR);
        total_len = ip_hdr_len + ntohs(pHdr->m_usPayloadlen);
        if(ipv6_checker && !ipv6_checker(pHdr))
        {
            return false;
        }
        ret = m_x3statistics.VerifyIPAddress(&pHdr->m_in6addrSourIp,&pHdr->m_in6addrDestIp,str_src_ip,str_dst_ip);
        m_pseu_ipv6_hdr.m_in6addrSourIp = pHdr->m_in6addrSourIp;
        m_pseu_ipv6_hdr.m_in6addrDestIp = pHdr->m_in6addrDestIp;
        m_pseu_ipv6_hdr.m_len = htonl(total_len - ip_hdr_len);
        m_pseu_ipv6_hdr.m_zero = 0;
        m_pseu_ipv6_hdr.m_ptcl = prot;
	break;
    }
    default:
    {
        LOG(ERROR,"unrecoginzied ip type");
        return false;
    }
    }
    if(m_dumpX3 == true)
    {
        LOG(DEBUG,"src ip: %s, dst ip: %s",str_src_ip,str_dst_ip);
    }
    return ret;
}
unsigned short CX3parser::parse_udp_hdr(unsigned char *body)
{
    UDP_HDR *pHdr = (UDP_HDR *)body;
    unsigned short src_port = ntohs(pHdr->m_usSourPort);
    unsigned short dst_port = ntohs(pHdr->m_usDestPort);
    if(m_dumpX3 == true)
    {
        LOG(DEBUG,"src port: %d, dst port: %d",src_port,dst_port);
    }
    if (m_payloadtype == X3_RTP)
    {
        if((src_port%2 == 0) && (dst_port%2 == 0))
        {
            m_real_rtptype = REAL_RTP;
            m_x3statistics.SetRtpPort(src_port,dst_port);

        }
        else if((src_port%2 != 0) && (dst_port%2 != 0))
        {
            m_real_rtptype = REAL_RTCP;
            //LOG(DEBUG,"this is RTCP msg");
            m_x3statistics.SetRtcpPort(src_port,dst_port);
        }
        else
        {
            LOG(ERROR,"something wrong, how could src and dst port are not even or odd at the same tiem?");
            return 0;
        }
    }
    else
    {
        LOG(ERROR,"parse_udp_hdr function should be called only when payload type is RTP/RTCP");
        return 0;
    }
    return ntohs(pHdr->m_usLength);
}

bool CX3parser::parse_tcp_hdr(unsigned char *hdr, int total_len, int &tcp_hdr_len, check_tcp_hdr_func tcp_checker)
{
    if (m_payloadtype != X3_MSRP)
    {
        LOG(ERROR,"parse_tcp_hdr function should be called only when payload type is MSRP");
        return false;
    }
    TCP_HDR *pHdr = (TCP_HDR *)hdr;
    unsigned short src_port = ntohs(pHdr->m_usSourPort);
    unsigned short dst_port = ntohs(pHdr->m_usDestPort);
    m_x3statistics.SetMsrpPort(src_port, dst_port);
    unsigned int seq_no = ntohl(pHdr->m_SequNum);
    if(!m_x3statistics.VerifyTCPSequence(seq_no))
    {
        return false;
    }
    unsigned int ack_seq_no = ntohl(pHdr->m_AcknowledgeNum);
    tcp_hdr_len = pHdr->m_len * 4;
    if (tcp_hdr_len != sizeof(TCP_HDR))
    {
        LOG(WARNING, "this tcp hdr contains options flag or is wrong, tcp hdr len: %d", tcp_hdr_len);
    }
    if(tcp_checker && !tcp_checker(pHdr)) {return false;}
    if(m_dumpX3 == true)
    {
        LOG(DEBUG, "src port: %d, dst port: %d",src_port,dst_port);
        LOG(DEBUG, "sequence number: %lu", seq_no);
        LOG(DEBUG, "ack sequence number: %lu", ack_seq_no);

    }
    if(!verifyTCPhdrChecksum(hdr, total_len))
    {
        LOG(ERROR, "tcp hdr checksum failed!");
        return false;
    }
    return true;
}
bool CX3parser::parse_rtcp(unsigned char *data, int rtcp_len)
{
    //the first bits of RTCP and RTP are the same, so here we just use the struct for RTP
    RTP_HDR *pHdr = (RTP_HDR *)data;
    if (pHdr->v != 2)
    {
        LOG(ERROR,"this is invalid RTP pkg");
        return false;
    }
    if (m_benableCompare == true)
    {
        return COMPARE_RTCP(data,rtcp_len,m_calldirection);
    }
    return true;
}

bool CX3parser::parse_rtp(unsigned char *data, int rtp_len)
{
    RTP_HDR *pHdr = (RTP_HDR *)data;
    if (pHdr->v != 2)
    {
        LOG(ERROR,"this is invalid RTP pkg");
        return false;
    }
    unsigned short rtp_seq = ntohs(pHdr->seq);
    if(m_dumpX3 == true)
    {
        LOG(DEBUG,"rtp sequence is %d, payload type is %d, SSRC is 0x%X, rtp len %d",rtp_seq,pHdr->pt,ntohl(pHdr->ssrc),rtp_len);
    }
    bool ret = m_x3statistics.SetRtpPT(pHdr->pt);
    bool b_EndofDTMF = false, bValidDTMF = false;
    if (ret == false && (bValidDTMF=IsValidDTMF(data+sizeof(RTP_HDR), rtp_len-sizeof(RTP_HDR),b_EndofDTMF)) == false)
    {
        LOG(ERROR,"payload_type changed and this is not DTMF pkg");
        return false;
    }
    if(bValidDTMF)
    {
        m_x3statistics.SetRtpDTMF();
    }
    ret = m_x3statistics.SetRtpSSRC(ntohl(pHdr->ssrc));
    if (ret == false)
    {
        LOG(ERROR,"SSRC changed");
        return false;
    }
    m_x3statistics.SetRtpSeq(rtp_seq);
    if (m_benableCompare == true)
    {
        if(b_EndofDTMF == true)
        {
            LOG(WARNING,"This is the DTMF pkg with E set to 1, for now, we'll ignore and not compare with the original pkg from pcap file");
        }
        else
        {
            bool ret = COMPARE_RTP(data,rtp_len,rtp_seq,m_calldirection);
            if(m_dumpX3 == true)
            {
               LOG(DEBUG,"Comparing RTP with original RTP from pcap file %s",ret==true?"succeeded":"failed");
            }
            return ret;
        }
    }
    /*if (m_calldirection == FROMTARGET)
    {
        int n = sendto(sock,data,rtp_len,0,(struct sockaddr *)&peeraddr,sizeof(peeraddr));
        if (n <= 0)
        {
            LOG(ERROR,"sending failed, %d:%s",errno,strerror(errno));
        }
        //LOG(DEBUG,"%d bytes sent out to vlc",n);
    }*/

    return true;
}

bool CX3parser::parse_msrp(unsigned char *data)
{
    if(m_dumpX3)
    {
        LOG(DEBUG,"dump the msrp data:\n%s", data);
    }
    return true;
}

bool CX3parser::verifyX3hdrformat()
{
    m_xmlrear = (unsigned char *)getX3hdrrear();
    if (!m_xmlrear)
    {
        LOG(ERROR,"failed to find the rear of x3 hdr");
        return false;
    }
    // <PayloadLength>280</PayloadLength>
    if (getElementValue("PayloadLength",tmp))
    {
        m_payloadlen = atoi(tmp);
        //LOG(DEBUG,"PayloadLength is %d",m_payloadlen);
    }
    else
    {
        LOG(ERROR,"failed to get PayloadLength tag value");
        return false;
    }

    string corId;
    // <li-tid>700</li-tid>
    if (getElementValue("li-tid",tmp) == false)
    {
        LOG(ERROR,"failed to get li-tid tag value");
        return false;
    }
    // <stamp>2016-09-05 03:04:52</stamp>
    if (getElementValue("stamp",tmp) == false)
    {
        LOG(ERROR,"failed to get stamp tag value");
        return false;
    }
    // <CallDirection>from-target</CallDirection>
    if (getElementValue("CallDirection",tmp))
    {
        if (strcmp("to-target",tmp) == 0)
        {
            m_calldirection = TO_DIRECTION;
        }
        else if (strcmp("from-target",tmp) == 0)
        {
            m_calldirection = FROM_DIRECTION;
        }
        else
        {
            LOG(ERROR,"unrecoginzied CallDirection: %s", tmp);
            return false;
        }
    }
    else
    {
        LOG(ERROR,"failed to get CallDirection tag value");
        return false;
    }
    // <Correlation-id>1-12c-19-1-ccd699</Correlation-id>
    if (getElementValue("Correlation-id",tmp) == false)
    {
        LOG(ERROR,"failed to get Correlation-id tag value");
        return false;
    }
    else
    {
        corId = string(tmp);
    }
    // <PayloadType>RTP</PayloadType>
    if (getElementValue("PayloadType",tmp))
    {
        if (strcmp("RTP",tmp) ==0 )
        {
            m_payloadtype = X3_RTP;
        }
        else if (strcmp("MSRP",tmp) == 0)
        {
            m_payloadtype = X3_MSRP;
        }
        else
        {
            LOG(ERROR,"unrecoginzied PayloadType: %s", tmp);
            return false;
        }
    }
    else
    {
        LOG(ERROR,"failed to get PayloadType tag value");
        return false;
    }
    m_x3statistics.SetX3PkgPara(corId,m_payloadtype,m_calldirection);
    return true;
}

void CX3parser::formatX3()
{
    memset(m_format_x3,0,sizeof(m_format_x3));
    char* data = formatX3xml();
    formatX3payload((unsigned char*)data);
}

char* CX3parser::formatX3xml()
{
    int r_anglebracket_num = 0;
    char *start_format_x3 = m_format_x3;
    assert(m_xmlrear != NULL);
    for(char *start = (char *)m_x3; start != (char *)m_xmlrear; start++)
    {   
        *start_format_x3++ = *start;
        if (*start == '>')
        {
            if ((start+1) == (char *)m_xmlrear)
            {
                break;
            }
            r_anglebracket_num++;
            if (r_anglebracket_num == 1 || r_anglebracket_num == 2
                    || (*(start+1) == '<' && *(start+2) == '/'))
            {
                *start_format_x3++ = '\n';
            }
            else if( *(start+1) == '<')
            {
                *start_format_x3++ = '\n';
                *start_format_x3++ = ' ';
                *start_format_x3++ = ' ';
            }
        }
    }
    *start_format_x3++ = '\n';
    return start_format_x3;
}

void CX3parser::formatX3payload(unsigned char *data)
{
    if (!data)
    {
        LOG(ERROR,"data is NULL");
    }
    unsigned char *start = (unsigned char*)m_xmlrear;
    if(m_payloadlen == -1)
    {
	LOG(ERROR,"Not got payloadlen, so cannot display x3 payload");
	return;
    }
    unsigned char *end = (unsigned char*)m_xmlrear + m_payloadlen;
    // if (m_payloadtype == X3_MSRP)
    // {
    //     memcpy(data,start,m_payloadlen);
    //     *(data + m_payloadlen) = '\0';
    //     return;
    // }
    char map[] = "0123456789abcdef";

    while(start != end)
    {
        *data++ = map[*start/16];
        *data++ = map[*start%16];
        start++;
    }
    //*data = '\n';
}


void CX3parser::initializeArguments()
{
    // TBD
}

void CX3parser::SetMinMaxSeq(int &min,int &max,unsigned short seq)
{
    if(min == -1)
    {
        max = min = seq;
        return;
    }
    int TOL = 10;
    if(seq < min && min-seq < TOL)
    {
        min = seq;
        return;
    }
    if(seq > max || (seq < min && min-seq > TOL))
    {
        max = seq;
        return;
    }
}

bool CX3parser::IsValidDTMF(u_char *dtmf, int dtmf_len, bool & b_end)
{
    if(dtmf_len != sizeof(DTMF_2833))
    {
        LOG(ERROR,"Invalid dtmf pkg len: %d",dtmf_len);
        return false;
    }
    DTMF_2833 * pDTMF = (DTMF_2833 *)dtmf;
    if(pDTMF->event <=16)
    {
        LOG(DEBUG,"Valid dtmf pkg, event: %d",pDTMF->event);
        (pDTMF->E == 1)?b_end=true:b_end=false;
        return true;
    }
    else
    {
        LOG(ERROR,"Invalid dtmf pkg, event: %d",pDTMF->event);
        return false;
    }
}
// size is in u_short unit
bool CX3parser:: verifyIPhdrChecksum(u_short *hdr, u_int size)
{   
    u_int cksum = 0;
    for(unsigned int i=0; i<size; i++)
    {
        cksum += hdr[i];
    }
    cksum = (cksum>>16) + (cksum&0xffff);
    cksum += (cksum>>16);
    u_short us_chksum = (u_short)(~cksum);
    bool ret;
    us_chksum == 0?ret = true:ret = false;
    return ret;
}
bool CX3parser::verifyTCPhdrChecksum(unsigned char *hdr, int size)
{
    char *buf = new (std::nothrow) char[65536];
    if(buf == NULL)
    {
        LOG(ERROR, "failed to allocate memory");
        return false;
    }
    if(m_iptype == IPV4)
    {
        memcpy(buf, &m_pseu_ipv4_hdr, sizeof(m_pseu_ipv4_hdr));
        memcpy(buf+sizeof(m_pseu_ipv4_hdr), hdr, size);
        size += sizeof(m_pseu_ipv4_hdr);
    }
    else
    {
        memcpy(buf, &m_pseu_ipv6_hdr, sizeof(m_pseu_ipv6_hdr));
        memcpy(buf+sizeof(m_pseu_ipv6_hdr), hdr, size);
        size += sizeof(m_pseu_ipv6_hdr);
    }
    
    u_int cksum = 0;
    u_short *start = (u_short *)buf;
    while(size > 1)
    {
        cksum += *start++;
        size -= sizeof(u_short);
    }
    if (size)
    {
        // LOG(DEBUG, "odd");
        cksum += *(u_char *)start;
        // u_short odd = 0;
        // *((u_char *)&odd) = *(u_char *)start;
        // cksum += odd;
    }
    cksum = (cksum>>16) + (cksum & 0xffff);
    cksum += (cksum>>16);
    u_short us_chksum = (u_short)(~cksum);
    if(m_dumpX3 == true)
    {
        LOG(DEBUG,"cheksum is %d", us_chksum);
    }
    bool ret;
    us_chksum == 0?ret = true:ret = false;
    delete[] buf;
    return ret;
}

#define CHECK(fieldname, field, value) \
do \
{ \
    if(field != value) \
    {\
        LOG(ERROR, "%s should be equal to %d, but now %d", fieldname, value, field); \
        return false;\
    }\
} while(0)

bool CX3parser::check_ipv4_hdr_for_msrp(IPv4_HDR *hdr)
{
    CHECK("DS", hdr->m_cTypeOfService, 0);
    CHECK("flags and offset", hdr->m_sSliceinfo, 0);
    CHECK("TTL", hdr->m_cTTL, 69);
    return true;
}
bool CX3parser::check_ipv6_hdr_for_msrp(IPv6_HDR *hdr)
{
    return false;
}
bool CX3parser::check_tcp_hdr_for_msrp(TCP_HDR *hdr)
{
    CHECK("ack seq number", hdr->m_AcknowledgeNum, 0);
    CHECK("reserve", hdr->m_reserve, 0);
    CHECK("URG", hdr->m_URG, 0);
    CHECK("ACK", hdr->m_ACK, 1);
    CHECK("PSH", hdr->m_PSH, 0);
    CHECK("RST", hdr->m_RST, 0);
    CHECK("SYN", hdr->m_SYN, 0);
    CHECK("FIN", hdr->m_FIN, 0);
    CHECK("Window Size", hdr->m_usWindowSize, 0);
    CHECK("Urgent Pointer", hdr->m_usUrgentPointer, 0);
    return true;
}