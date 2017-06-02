#ifndef _UTIL_H_X3PARSER22t0
#define _UTIL_H_X3PARSER22t0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <stdarg.h>
#include <vector>
#include <map>
#include <bitset>
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
#include <bitset>
#include "log.h"

#define IP_STRING_LEN 256


#define        X3_RTP      0
#define        X3_MSRP     1
#define        X3_NOTYPE   2

#define   TO_DIRECTION     0
#define   FROM_DIRECTION   1
#define   NONE_DIRECTION   2

#define  SRC              0
#define  DST              1

#define       REAL_RTP    0
#define       REAL_RTCP   1
#define       REAL_NO     2

#define        IPV4      4
#define        IPV6      6
#define        NOIP      2


class CBaseInfo
{
public:
    unsigned int from_target_num;
    unsigned int to_target_num;
    unsigned int m_cur_direction;
    //unsigned int *cur_num;
    CBaseInfo()
    {
        from_target_num = 0;
        to_target_num   = 0;
        m_cur_direction = NONE_DIRECTION;
    }
    void IncreaseNum(unsigned int direction)
    {
        m_cur_direction=direction;
        (direction == FROM_DIRECTION)?from_target_num++:to_target_num++;
    }

    template<typename T1, typename T2>
    bool SetAndVerifyValue(int package_no, T1& argu, const T2 newValue)
    {
        if(package_no > 1)
        {
            if(argu != newValue)
            {
                LOG(DEBUG,"maybe something is wrong, the previous is 0x%x, the current is 0x%x, need to check further",argu, newValue);
                return false;
            }
        }
        else
        {
            argu = newValue;
        }
        return true;
    }
};

class CRtpPortPairInfo: public CBaseInfo
{
public:

    CRtpPortPairInfo(unsigned short target_port, unsigned short uag_port, unsigned int direction)
    {
        //m_cur_direction = direction;
        IncreaseNum(direction);
        m_target_port = target_port;
        m_uag_port    = uag_port;
        dtmf_from_target = false;
        dtmf_to_target = false;

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
        //LOG(DEBUG,"real_sum %d, min seq %d, max seq %d",real_sum,min,max);
        if(real_sum == 0)
            return 0;
        unsigned expected_sum  = (min <= max)?(max-min+1):(65536-min+max+1);
        assert(expected_sum >= real_sum);
        float rate =  (float)(expected_sum - real_sum) / expected_sum * 100;
        //printf("it is: %d, %d, %.6f\n",expected_sum - real_sum,expected_sum,rate);
        return rate;
    }
    bool VerifyRtpPT(unsigned int pt)
    {
        return SetAndVerifyValue(from_target_num+to_target_num,payload_type,pt);
    }
    void SetDTMF()
    {
        (m_cur_direction == FROM_DIRECTION)?dtmf_from_target = true:dtmf_to_target = true;
    }
    bool VerifySSRC(unsigned int ssrc)
    {
        return (m_cur_direction == FROM_DIRECTION)?SetAndVerifyValue(from_target_num,ssrc_from_target,ssrc): \
               SetAndVerifyValue(to_target_num,ssrc_to_target,ssrc);
    }
    void SetRtpSeq(unsigned short rtp_seq)
    {
        if(m_cur_direction == FROM_DIRECTION)
        {
            from_target_seqset.set(rtp_seq);
            SetMinMaxSeq(from_target_minseq,from_target_maxseq,rtp_seq);
        }
        else
        {
            to_target_seqset.set(rtp_seq);
            SetMinMaxSeq(to_target_minseq,to_target_maxseq,rtp_seq);
        }
    }
    unsigned short m_target_port;
    unsigned short m_uag_port;

    std::bitset<65536> from_target_seqset;
    std::bitset<65536> to_target_seqset;
    int   payload_type;
    unsigned int   ssrc_from_target;
    unsigned int   ssrc_to_target;
    int            from_target_minseq;
    int            from_target_maxseq;
    int            to_target_minseq;
    int            to_target_maxseq;
    bool           dtmf_from_target;
    bool           dtmf_to_target;
private:
    void SetMinMaxSeq(int &min,int &max,unsigned short seq)
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
};

class CRtcpPortPairInfo: public CBaseInfo
{
public:

    unsigned short m_target_port;
    unsigned short m_uag_port;
    CRtcpPortPairInfo(unsigned short target_port,unsigned short uag_port, unsigned int direction)
    {
        m_target_port = target_port;
        m_uag_port = uag_port;
        IncreaseNum(direction);
    }
};

class CMsrpInfo: public CBaseInfo
{
private:
    ;
};

class CRtpRtcpInfo: public CBaseInfo
{
private:
    char *ip_addr_map[2][2];


public:

    char target_ip[IP_STRING_LEN];
    char uag_ip[IP_STRING_LEN];
    int  m_iptype;
    std::vector<CRtpPortPairInfo> vec_rtp_pair_info;
    std::vector<CRtcpPortPairInfo> vec_rtcp_pair_info;
    std::vector<CRtpPortPairInfo>::iterator m_cur_rtp_iter;
    std::vector<CRtcpPortPairInfo>::iterator m_cur_rtcp_iter;
    CRtpRtcpInfo();
    ~CRtpRtcpInfo()
    {

    }
    bool VerifyIPType(unsigned int ip_type)
    {
        return SetAndVerifyValue(from_target_num+to_target_num,m_iptype,ip_type);
    }
    bool VerifyIPAddress(void *src, void *dst, int af);
    void SetRtpPort(unsigned short src_port, unsigned short dst_port);
    void SetRtcpPort(unsigned short src_port, unsigned short dst_port);
    std::vector<CRtpPortPairInfo>::iterator findExistedRtpPortPair(unsigned short target_port,unsigned short uag_port);
    std::vector<CRtcpPortPairInfo>::iterator findExistedRtcpPortPair(unsigned short target_port,unsigned short uag_port);
};



class CSingleTargetInfo
{
public:
    unsigned int m_cur_x3body_type;

    CMsrpInfo    m_MsrpInfo;
    CRtpRtcpInfo m_RtpRtcpInfo;
public:
    CSingleTargetInfo(unsigned int x3body_type, unsigned int direction);
    // desgin the default constructor just for map operator[] compiling pass requirement, should use .at() function to replace [] in C++11
    CSingleTargetInfo()
    {
	LOG(ERROR,"this should never be called, just for map operator[] compiling pass purpose");
	exit(1);
    }
    ~CSingleTargetInfo();
    void SetX3PkgParaForSingle(unsigned int x3body_type, unsigned int direction);
    void SetDirection(unsigned int direction);

};

class CX3Statistics
{
private:

    std::map<std::string,CSingleTargetInfo> m_x3info;
    std::string m_cur_corId;

public:
    CX3Statistics();
    ~CX3Statistics();
    bool VerifyIPAddress(void *src, void *dst, int af);
    bool VerifyIPType(unsigned int ip_type);
    void SetX3PkgPara(std::string & corId, unsigned int x3body_type, unsigned int direction);
    void SetRtpPort(unsigned short src_port, unsigned short dst_port);
    void SetRtcpPort(unsigned short src_port, unsigned short dst_port);
    bool SetRtpPT(unsigned int pt);
    void SetRtpDTMF();
    bool SetRtpSSRC(unsigned int ssrc);
    void SetRtpSeq(unsigned short rtp_seq);
    void OutputStatics();


};


#endif
