#include "udpx3cachequeue.h"
CUdpX3CacheQueue::CUdpX3CacheQueue()
{
    capacity = 0;
    rear   = -1;
    head  = 0;
    memset(m_udp_x3_array, 0x0, sizeof(m_udp_x3_array));
}
CUdpX3CacheQueue::~CUdpX3CacheQueue()
{
    for(int i=0; i<MAX_CACHED_UDP_X3_NUM; i++)
    {   
        if (m_udp_x3_array[i].flag)
        {
            LOG(WARNING,"there is cached x3 not handled");
            delete [] m_udp_x3_array[i].p_pkg;
        }      
    }
}
int CUdpX3CacheQueue::EnQueue(const unsigned char *p, int len)
{
    if (IsFull())
    {
        LOG(WARNING,"the queue is full and cannot enqueue any element");
        return -1;
    }
    rear = (rear+1)%MAX_CACHED_UDP_X3_NUM;
    if (m_udp_x3_array[rear].flag)
    {
        LOG(WARNING,"the queue is not full but the rear is occupied");
        return -1;
    }
    m_udp_x3_array[rear].p_pkg = new u_char[len];
    if (!m_udp_x3_array[rear].p_pkg)
    {
        LOG(WARNING,"failed to allocate new memory");
        return -1;
    }
    memcpy(m_udp_x3_array[rear].p_pkg,p,len);
    m_udp_x3_array[rear].pkg_len = len;
    m_udp_x3_array[rear].flag = 1;
    capacity++;
    return rear;
}
UDP_X3* CUdpX3CacheQueue::DeQueue()
{
    if (IsEmpty())
    {
        //LOG(WARNING,"the queue is empty");
        return NULL;
    }
    int old_head = head;
    capacity--;
    m_udp_x3_array[old_head].flag = 0;
    head = (head+1)%MAX_CACHED_UDP_X3_NUM;
    //LOG(DEBUG,"Have got the head of the queue: %d, head got out of queue", old_head);
    return &m_udp_x3_array[old_head];
}
/*UDP_X3* CUdpX3CacheQueue::GetHeadOfQueue()
{
    if (IsEmpty())
    {
        LOG(WARNING,"the queue is empty, this should not happen--failed to enqueue or multi-thread conflict?");
        return NULL;
    }
    LOG(DEBUG,"Have got the head of the queue: %d", head);
    return &m_udp_x3_array[head];
}*/
void CUdpX3CacheQueue::FreeCachedUdpX3(UDP_X3 *p)
{
    LOG(DEBUG,"free the memory for UDP_X3");
    delete [] p->p_pkg;
    p->p_pkg = NULL;
    p->pkg_len = 0;
}
