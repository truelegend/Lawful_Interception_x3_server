#include "x3statistics.h"
#include <errno.h>
using namespace std;

CSingleTargetInfo::CSingleTargetInfo(unsigned int x3body_type, unsigned int direction)
{
    m_cur_x3body_type = x3body_type;
    SetDirection(direction);
}

CSingleTargetInfo::~CSingleTargetInfo()
{

}

void CSingleTargetInfo::SetX3PkgParaForSingle(unsigned int x3body_type, unsigned int direction)
{
    if(m_cur_x3body_type != x3body_type)
    {
        LOG(ERROR,"the X3 messages with the same correlation-id should not have different payload_types");
        exit(1);
    }
    SetDirection(direction);
}

void CSingleTargetInfo::SetDirection(unsigned int direction)
{
    (m_cur_x3body_type == X3_RTP)?m_RtpRtcpInfo.IncreaseNum(direction):m_MsrpInfo.IncreaseNum(direction);
}

CRtpRtcpInfo::CRtpRtcpInfo()
{
    m_iptype = NOIP;
    memset(uag_ip,0,IP_STRING_LEN);
    memset(target_ip,0,IP_STRING_LEN);
    // should not assign here in case of copy construct call using vector/map...
    /*
    ip_addr_map[TO_DIRECTION][SRC] = uag_ip;
    ip_addr_map[TO_DIRECTION][DST] = target_ip;
    ip_addr_map[FROM_DIRECTION][SRC] = target_ip;
    ip_addr_map[FROM_DIRECTION][DST] = uag_ip;
    */
}

bool CRtpRtcpInfo::VerifyIPAddress(void *src, void *dst, int af)
{
    if ((from_target_num+to_target_num) == 1)
    {
        ip_addr_map[TO_DIRECTION][SRC] = uag_ip;
        ip_addr_map[TO_DIRECTION][DST] = target_ip;
        ip_addr_map[FROM_DIRECTION][SRC] = target_ip;
        ip_addr_map[FROM_DIRECTION][DST] = uag_ip;
        if(!inet_ntop(af,src,ip_addr_map[m_cur_direction][SRC],IP_STRING_LEN))
        {
            LOG(ERROR,"failed to get ip addr");
            return false;
        }
        if(!inet_ntop(af,dst,ip_addr_map[m_cur_direction][DST],IP_STRING_LEN))
        {
            LOG(ERROR,"failed to get ip addr");
            return false;
        }
    }
    else
    {
        char tmp_target_ip[IP_STRING_LEN];
        char tmp_uag_ip[IP_STRING_LEN];
        char *tmp_ip_addr_map[2][2];
        tmp_ip_addr_map[TO_DIRECTION][SRC] = tmp_uag_ip;
        tmp_ip_addr_map[TO_DIRECTION][DST] = tmp_target_ip;
        tmp_ip_addr_map[FROM_DIRECTION][SRC] = tmp_target_ip;
        tmp_ip_addr_map[FROM_DIRECTION][DST] = tmp_uag_ip;

        if(!inet_ntop(af,src,tmp_ip_addr_map[m_cur_direction][SRC],IP_STRING_LEN))
        {
            LOG(ERROR,"failed to get ip addr");
            return false;
        }
        if(!inet_ntop(af,dst,tmp_ip_addr_map[m_cur_direction][DST],IP_STRING_LEN))
        {
            LOG(ERROR,"failed to get ip addr");
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

void CRtpRtcpInfo::SetRtpPort(unsigned short src_port, unsigned short dst_port)
{
    unsigned short target_port = (m_cur_direction==FROM_DIRECTION)?src_port:dst_port;
    unsigned short uag_port = (m_cur_direction==FROM_DIRECTION)?dst_port:src_port;
    vector<CRtpPortPairInfo>::iterator iter = findExistedRtpPortPair(target_port, uag_port);
    if(iter == vec_rtp_pair_info.end())
    {
        CRtpPortPairInfo rtp_port_pair(target_port,uag_port,m_cur_direction);
        vec_rtp_pair_info.push_back(rtp_port_pair);
        m_cur_rtp_iter = findExistedRtpPortPair(target_port,uag_port);
    }
    else
    {
        iter->IncreaseNum(m_cur_direction);
        m_cur_rtp_iter = iter;
    }
}

void CRtpRtcpInfo::SetRtcpPort(unsigned short src_port, unsigned short dst_port)
{
    unsigned short target_port = (m_cur_direction==FROM_DIRECTION)?src_port:dst_port;
    unsigned short uag_port = (m_cur_direction==FROM_DIRECTION)?dst_port:src_port;
    vector<CRtcpPortPairInfo>::iterator iter = findExistedRtcpPortPair(target_port, uag_port);
    if(iter == vec_rtcp_pair_info.end())
    {
        CRtcpPortPairInfo rtcp_port_pair(target_port,uag_port,m_cur_direction);
        vec_rtcp_pair_info.push_back(rtcp_port_pair);
        m_cur_rtcp_iter = findExistedRtcpPortPair(target_port,uag_port);
    }
    else
    {
        iter->IncreaseNum(m_cur_direction);
        m_cur_rtcp_iter = iter;
    }
}
vector<CRtpPortPairInfo>::iterator CRtpRtcpInfo::findExistedRtpPortPair(unsigned short target_port,unsigned short uag_port)
{
    vector<CRtpPortPairInfo>::iterator iter;
    for(iter = vec_rtp_pair_info.begin(); iter != vec_rtp_pair_info.end(); ++iter)
    {
        if (iter->m_target_port == target_port
                && iter->m_uag_port == uag_port)
        {
            return iter;
        }
    }
    return iter;
}

vector<CRtcpPortPairInfo>::iterator CRtpRtcpInfo::findExistedRtcpPortPair(unsigned short target_port,unsigned short uag_port)
{
    vector<CRtcpPortPairInfo>::iterator iter;
    for(iter = vec_rtcp_pair_info.begin(); iter != vec_rtcp_pair_info.end(); ++iter)
    {
        if (iter->m_target_port == target_port
                && iter->m_uag_port == uag_port)
        {
            return iter;
        }
    }
    return iter;
}

CX3Statistics::CX3Statistics()
{

}

CX3Statistics::~CX3Statistics()
{

}
void CX3Statistics::SetX3PkgPara(string &corId, unsigned int x3body_type, unsigned int direction)
{
    m_cur_corId = corId;
    if(m_x3info.find(m_cur_corId) == m_x3info.end())
    {
        CSingleTargetInfo singleInfo(x3body_type,direction);
        //m_x3info[m_cur_corId] = singleInfo;
        m_x3info.insert(pair<string,CSingleTargetInfo>(m_cur_corId,singleInfo));
    }
    else
    {
        //m_x3info[m_cur_corId].SetX3PkgParaForSingle(x3body_type,direction);
        m_x3info.at(m_cur_corId).SetX3PkgParaForSingle(x3body_type,direction);
    }
}
bool CX3Statistics::VerifyIPType(unsigned int ip_type)
{
    return m_x3info.at(m_cur_corId).m_RtpRtcpInfo.VerifyIPType(ip_type);
}

bool CX3Statistics::VerifyIPAddress(void *src, void *dst, int af)
{
    return m_x3info.at(m_cur_corId).m_RtpRtcpInfo.VerifyIPAddress(src, dst, af);
}

void CX3Statistics::SetRtpPort(unsigned short src_port, unsigned short dst_port)
{
    m_x3info.at(m_cur_corId).m_RtpRtcpInfo.SetRtpPort(src_port,dst_port);
}
void CX3Statistics::SetRtcpPort(unsigned short src_port, unsigned short dst_port)
{
    m_x3info.at(m_cur_corId).m_RtpRtcpInfo.SetRtcpPort(src_port,dst_port);
}

bool CX3Statistics::SetRtpPT(unsigned int pt)
{
    return m_x3info.at(m_cur_corId).m_RtpRtcpInfo.m_cur_rtp_iter->VerifyRtpPT(pt);
}

void CX3Statistics::SetRtpDTMF()
{
    m_x3info.at(m_cur_corId).m_RtpRtcpInfo.m_cur_rtp_iter->SetDTMF();
}
bool CX3Statistics::SetRtpSSRC(unsigned int ssrc)
{
    return m_x3info.at(m_cur_corId).m_RtpRtcpInfo.m_cur_rtp_iter->VerifySSRC(ssrc);
}

void CX3Statistics::SetRtpSeq(unsigned short rtp_seq)
{
    m_x3info.at(m_cur_corId).m_RtpRtcpInfo.m_cur_rtp_iter->SetRtpSeq(rtp_seq);
}

void CX3Statistics::OutputStatics()
{
    LOG_RAW("target number: %d", m_x3info.size());
    for(map<string,CSingleTargetInfo>::iterator iter = m_x3info.begin(); iter != m_x3info.end(); ++iter)
    {
        LOG_RAW("Correlation-id:%s",iter->first.c_str());
        if(iter->second.m_cur_x3body_type == X3_RTP)
        {
            LOG_RAW("from_target_num: %d, to_target_num: %d",iter->second.m_RtpRtcpInfo.from_target_num,iter->second.m_RtpRtcpInfo.to_target_num);
            LOG_RAW("target_ip: %s, uag_ip: %s",iter->second.m_RtpRtcpInfo.target_ip,iter->second.m_RtpRtcpInfo.uag_ip);

            vector<CRtpPortPairInfo> &vec_int_rtp = iter->second.m_RtpRtcpInfo.vec_rtp_pair_info;
            for(vector<CRtpPortPairInfo>::iterator iter_vec = vec_int_rtp.begin(); iter_vec != vec_int_rtp.end(); ++iter_vec)
            {
                LOG_RAW("RTP info:");
                float from_target_loss_rate = iter_vec->GetFromRtpLossRate();
                float to_target_loss_rate = iter_vec->GetToRtpLossRate();
                LOG_RAW("target port: %d, uag port: %d, from_target_num: %d, to_target_num: %d, rtp payload type: %d, ssrc from target: 0x%X, ssrc to target: 0x%X, \
from_target_loss_rate: %.3f%, to_target_loss_rate: %.3f%",
                        iter_vec->m_target_port,iter_vec->m_uag_port,iter_vec->from_target_num,iter_vec->to_target_num,
                        iter_vec->payload_type,iter_vec->ssrc_from_target,iter_vec->ssrc_to_target,from_target_loss_rate,to_target_loss_rate);
            }

            vector<CRtcpPortPairInfo> &vec_int_rtcp = iter->second.m_RtpRtcpInfo.vec_rtcp_pair_info;
            for(vector<CRtcpPortPairInfo>::iterator iter_vec = vec_int_rtcp.begin(); iter_vec != vec_int_rtcp.end(); ++iter_vec)
            {
                LOG_RAW("RTCP info:");
                //float from_target_loss_rate = iter->GetFromRtpLossRate();
                //float to_target_loss_rate = iter->GetToRtpLossRate();
                LOG_RAW("target port: %d, uag port: %d, from_target_num: %d, to_target_num: %d",
                        iter_vec->m_target_port,iter_vec->m_uag_port,iter_vec->from_target_num,iter_vec->to_target_num);
            }

        }
        else //MSRP
        {
            LOG(DEBUG,"MSRP from_target_num: %d, to_target_num: %d",iter->second.m_MsrpInfo.from_target_num,iter->second.m_MsrpInfo.to_target_num);
        }
    }
}