#include "x3parser.h"
#include <errno.h>
using namespace std;

CX3parser::CX3parser()
{
    m_payloadlen = -1;
    m_payloadtype = NOTYPE;
    m_calldirection = NODIRECTION;
    m_real_rtptype = REAL_NO;

    m_xmlrear      = NULL;
    memset(m_format_x3,'\0',sizeof(m_format_x3));

    m_iptype       = NOIP;
    x3_num = 0;
    from_target_num = 0;
    to_target_num = 0;
    from_rtp_num = 0;
    from_rtcp_num = 0;
    from_msrp_num = 0;
    to_rtp_num = 0;
    to_rtcp_num = 0;
    to_msrp_num = 0;
    target_ip = NULL;
    uag_ip = NULL;

    //struct sockaddr_in peeraddr;
    sock = socket(AF_INET,SOCK_DGRAM,0);
    assert(sock != -1);
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(40000);
    peeraddr.sin_addr.s_addr = inet_addr("10.2.1.75");

    m_benableCompare = false;
    m_ipchecksum = false;
}

CX3parser::~CX3parser()
{
    delete[] target_ip;
    delete[] uag_ip;
}


bool CX3parser::parse_x3(unsigned char *x3, int x3_len)
{
    if (x3 == NULL || x3_len == 0)
    {
        LOG(ERROR,"wrong parameters");
        return false;
    }
    //LOG(DEBUG,"x3 len is %d",x3_len);
    //x3[x3_len] = '\0';
    m_x3 = x3;
    m_x3_len = x3_len;

    if (verifyX3hdrformat() == false)
    {
        LOG(ERROR,"wrong x3 hdr format");
        return false;
    }
    x3_num++;

    bool ret = parse_x3body(m_x3+m_x3_len-m_payloadlen,m_payloadlen);
    if(m_dumpX3 == true)
    {
        formatX3();
        LOG(DEBUG,"dump the received x3 data:\n%s\n", m_format_x3);
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
    m_xmlrear = (unsigned char *)getX3hdrrear();
    if (!m_xmlrear)
    {
        LOG(ERROR,"failed to find the rear of x3 hdr");
        return false;
    }
    if (m_xmlrear != body)
    {
        LOG(ERROR,"this should be wrong, the beginning of x3 body is not correct");
        return false;
    }
    //LOG(DEBUG,"Got the correct beginning of x3 body");
    if(m_payloadtype == MSRP)
    {
	(m_calldirection == FROMTARGET)?from_msrp_num++:to_msrp_num++;
        LOG(DEBUG,"It is MSRP, the xml body doesn't contain ip hdr/etc., so won't deocde further");
        return true;
    }

    unsigned char *start = body;
    switch(*start>>4)
    {
    case 4:
        if (SetAndVerifyValue(m_iptype,NOIP,IPV4) == false)
        {
	    LOG(ERROR,"ip type cannot change!");
            return false;
        }
        break;
    case 6:
        if (SetAndVerifyValue(m_iptype,NOIP,IPV6) == false)
        {
	    LOG(ERROR,"ip type cannot change!");
            return false;
        }
        break;
    default:
        LOG(ERROR,"unrecoginzied ip type");
        return false;
    }

    int ip_hdr_len, total_len;
    if (parse_ip_hdr(start,ip_hdr_len,total_len) == false)
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
    if (m_payloadtype == MSRP)
    {
        parse_msrp((unsigned char*)start);
    }
    else if (m_real_rtptype == REAL_RTP)
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

bool CX3parser::parse_ip_hdr(unsigned char *body, int &ip_hdr_len, int &total_len)
{
    switch(m_iptype)
    {
    case IPV4:
    {
        IPv4_HDR *pHdr = (IPv4_HDR *)body;
        if (pHdr->m_cTypeOfProtocol != 17) // for RTP/RTCP, it is over UDP
        {
            LOG(ERROR,"the upper protocol is not UDP");
            return false;
        }
        ip_hdr_len = (pHdr->m_cVersionAndHeaderLen & 0x0f) *4;
	if (ip_hdr_len != sizeof(IPv4_HDR))
	{
	    LOG(ERROR,"the decoded ipv4 hdr is not correct");
	    return false;    
	}
	if (m_ipchecksum == true && verifyIPhdrChecksum((u_short *)pHdr,ip_hdr_len/2) == false)
	{
	    LOG(ERROR,"ip hdr checksum failed");                
	    return false;
	}
 	total_len = ntohs(pHdr->m_sTotalLenOfPacket);
        return getIPaddrAndVerify(&pHdr->m_in4addrSourIp,&pHdr->m_in4addrDestIp,AF_INET);
    }
    case IPV6:
    {
        IPv6_HDR *pHdr = (IPv6_HDR *)body;
        if (pHdr->m_ucNexthdr != 17) // for RTP/RTCP, it is over UDP
        {
            LOG(ERROR,"the upper protocol is not UDP");
            return false;
        }
        // Won't consider extended ipv6 hdr for now
        ip_hdr_len = sizeof(IPv6_HDR);
        total_len = ip_hdr_len + ntohs(pHdr->m_usPayloadlen);
        return getIPaddrAndVerify(&pHdr->m_in6addrSourIp,&pHdr->m_in6addrDestIp,AF_INET6);
    }
    default:
    {
        LOG(ERROR,"unrecoginzied ip type");
        return false;
    }
    }

}
unsigned short CX3parser::parse_udp_hdr(unsigned char *body)
{
    UDP_HDR *pHdr = (UDP_HDR *)body;
    unsigned short src_port = ntohs(pHdr->m_usSourPort);
    unsigned short dst_port = ntohs(pHdr->m_usDestPort);
    //LOG(DEBUG,"source port: %d",src_port);
    //LOG(DEBUG,"dst port: %d",dst_port);
    if(false == setPortPairInfo(src_port,dst_port))
    {
        return 0;
    }
    if (m_payloadtype == RTP)
    {
        if((src_port%2 == 0) && (dst_port%2 == 0))
        {
            m_real_rtptype = REAL_RTP;
            //LOG(DEBUG,"this is RTP msg");
            (m_calldirection == FROMTARGET)?from_rtp_num++:to_rtp_num++;
        }
        else if((src_port%2 != 0) && (dst_port%2 != 0))
        {
            m_real_rtptype = REAL_RTCP;
            LOG(DEBUG,"this is RTCP msg");
            (m_calldirection == FROMTARGET)?from_rtcp_num++:to_rtcp_num++;
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
    LOG(DEBUG,"rtp sequence is %d, payload type is %d, SSRC is 0x%X, rtp len %d",rtp_seq,pHdr->pt,ntohl(pHdr->ssrc),rtp_len);

    bool ret = SetAndVerifyValue(m_cur_iter->payload_type,-1,pHdr->pt);
    bool b_EndofDTMF = false;
    if (ret == false && IsValidDTMF(data+sizeof(RTP_HDR), rtp_len-sizeof(RTP_HDR),b_EndofDTMF) == false)
    {
        LOG(ERROR,"payload_type changed and this is not DTMF pkg");
        return false;
    }

    switch(m_calldirection)
    {
    case FROMTARGET:
    {
        bool ret = SetAndVerifyValue(m_cur_iter->ssrc_from_target,0,ntohl(pHdr->ssrc));
        if (ret == false)
        {
	    LOG(ERROR,"from_target ssrc changed");   
            return false;
        }
        m_cur_iter->from_target_seqset.set(rtp_seq);
        SetMinMaxSeq(m_cur_iter->from_target_minseq,m_cur_iter->from_target_maxseq,rtp_seq);
        break;
    }
    case TOTARGET:
    {
        bool ret = SetAndVerifyValue(m_cur_iter->ssrc_to_target,0,ntohl(pHdr->ssrc));
        if (ret == false)
        {
	    LOG(ERROR,"to_target ssrc changed");      
            return false;
        }
        m_cur_iter->to_target_seqset.set(rtp_seq);
        SetMinMaxSeq(m_cur_iter->to_target_minseq,m_cur_iter->to_target_maxseq,rtp_seq);
        break;
    }
    }
    if (m_benableCompare == true)
    {
	if(b_EndofDTMF == true)
	{
	    LOG(WARNING,"This is the DTMF pkg with E set to 1, for now, we'll ignore and not compare with the original pkg from pcap file");   
	}
	else
	{
            return COMPARE_RTP(data,rtp_len,rtp_seq,m_calldirection);
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
    return true;
}

bool CX3parser::verifyX3hdrformat()
{
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
            m_calldirection = TOTARGET;
            to_target_num++;
        }
        else if (strcmp("from-target",tmp) == 0)
        {
            m_calldirection = FROMTARGET;
            from_target_num++;
        }
        else
        {
            LOG(ERROR,"unrecoginzied CallDirection: %s", tmp);
            return false;
        }
        //LOG(DEBUG,"CallDirection is %s",tmp);
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
	string value(tmp);
        if(m_mapCorId.find(value) == m_mapCorId.end())
	{
	    m_mapCorId[value] = 1;
	}
	else
	{
	    m_mapCorId[value]++;	
	}
    }
    // <PayloadType>RTP</PayloadType>
    if (getElementValue("PayloadType",tmp))
    {
        if (strcmp("RTP",tmp) ==0 )
        {
            m_payloadtype = RTP;
        }
        else if (strcmp("MSRP",tmp) == 0)
        {
            m_payloadtype = MSRP;
        }
        else
        {
            LOG(ERROR,"unrecoginzied PayloadType: %s", tmp);
            return false;
        }
        //LOG(DEBUG,"PayloadType is %s",tmp);
    }
    else
    {
        LOG(ERROR,"failed to get PayloadType tag value");
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
    return true;
}
bool CX3parser::getIPaddrAndVerify(void *src, void *dst, int af)
{
    if (target_ip == NULL && uag_ip == NULL)
    {
        target_ip = new char[IP_STRING_NUM];
        uag_ip    = new char[IP_STRING_NUM];
        switch(m_calldirection)
        {
        case TOTARGET:
            if(!inet_ntop(af,src,uag_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            if(!inet_ntop(af,dst,target_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            break;
        case FROMTARGET:
            if(!inet_ntop(af,dst,uag_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            if(!inet_ntop(af,src,target_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            break;
        default:
            break;
        }
    }
    else
    {
        char tmp_target_ip[IP_STRING_NUM];
        char tmp_uag_ip[IP_STRING_NUM];
        switch(m_calldirection)
        {
        case TOTARGET:
            if(!inet_ntop(af,src,tmp_uag_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            if(!inet_ntop(af,dst,tmp_target_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            break;
        case FROMTARGET:
            if(!inet_ntop(af,dst,tmp_uag_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            if(!inet_ntop(af,src,tmp_target_ip,IP_STRING_NUM)) {
                LOG(ERROR,"failed to get ip addr");
                return false;
            }
            break;
        default:
            LOG(ERROR,"error direction");
            return false;
        }
        if(strcmp(target_ip,tmp_target_ip) != 0) {
            LOG(ERROR,"target IP changed?! The previous ip %s, the current ip %s",target_ip,tmp_target_ip);
            return false;
        }
        if(strcmp(uag_ip,tmp_uag_ip) != 0) {
            LOG(ERROR,"uag IP changed?! The previous ip %s, the current ip %s",target_ip,tmp_target_ip);
            return false;
        }
    }
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
    unsigned char *end = (unsigned char*)m_xmlrear+m_payloadlen;

    if (m_payloadtype == MSRP)
    {
        memcpy(data,start,m_payloadlen);
	*(data + m_payloadlen) = '\0';
        return;
    }
    char map[] = "0123456789abcdef";

    while(start != end)
    {
        *data++ = map[*start/16];
        *data++ = map[*start%16];
        start++;
    }
    *data = '\n';
}

/*bool CX3parser::setAndVerifyIPtype(int iptype)
{
    if (m_iptype == NOIP)
    {
        m_iptype = iptype;
    }
    else
    {
        if (m_iptype != iptype)
        {
            LOG(ERROR,"The IP address type in X3 body changed, should be something wrong, the previous is IPv%d, the current is IPv%d",m_iptype,iptype);
            return false;
        }
    }
    return true;
}*/

void CX3parser::initializeArguments()
{
    // TBD
}


bool CX3parser::setPortPairInfo(unsigned short src_port, unsigned short dst_port)
{
    switch(m_calldirection)
    {
    case TOTARGET:
    {
        vector<PORT_PARI_INFO>::iterator iter = findExistedPortPair(dst_port,src_port);
        if(iter == vecPort_pair_info.end())
        {
            PORT_PARI_INFO portpartinfo(dst_port,src_port,0,1);
            vecPort_pair_info.push_back(portpartinfo);
            m_cur_iter = findExistedPortPair(dst_port,src_port);
        }
        else
        {
            iter->to_target_num++;
            m_cur_iter = iter;
        }
        break;
    }
    case FROMTARGET:
    {
        vector<PORT_PARI_INFO>::iterator iter = findExistedPortPair(src_port,dst_port);
        if(iter == vecPort_pair_info.end())
        {
            PORT_PARI_INFO portpartinfo(src_port,dst_port,1,0);
            vecPort_pair_info.push_back(portpartinfo);
            m_cur_iter = findExistedPortPair(src_port,dst_port);
        }
        else
        {
            iter->from_target_num++;
            m_cur_iter = iter;
        }
        break;
    }
    default:
    {
        LOG(ERROR,"wrong direction");
        return false;
    }
    }
    return true;
}
vector<PORT_PARI_INFO>::iterator CX3parser::findExistedPortPair(unsigned short target_port,unsigned short uag_port)
{
    vector<PORT_PARI_INFO>::iterator iter;
    for(iter = vecPort_pair_info.begin(); iter != vecPort_pair_info.end(); ++iter)
    {
        if (iter->target_port == target_port
                && iter->uag_port == uag_port)
        {
            return iter;
        }
    }
    return iter;
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
	pDTMF->E == 1?b_end=true:b_end=false;
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
    for(unsigned int i=0;i<size;i++)
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

