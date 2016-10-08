#ifndef _X3_QUEUE_H
#define _X3_QUEUE_H

#include "log.h"
#define MAX_CACHED_UDP_X3_NUM 50000
struct UDP_X3
{
    int pkg_len;
    u_char* p_pkg;
    int flag;
};
class CUdpX3CacheQueue
{
public:
    CUdpX3CacheQueue();
    ~CUdpX3CacheQueue();
    int EnQueue(const unsigned char *p, int len);
    UDP_X3* DeQueue();
    void FreeCachedUdpX3(UDP_X3 *p);
    //RAW_RTP* GetHeadOfQueue();
    inline bool IsFull() {
        return (capacity >= MAX_CACHED_UDP_X3_NUM)?true:false;
    };
    inline bool IsEmpty() {
        return (capacity == 0)?true:false;
    };


private:

    int capacity;
    int rear;
    int head;
    UDP_X3 m_udp_x3_array[MAX_CACHED_UDP_X3_NUM];

};

#endif
