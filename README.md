Design and implement one simulated Lawful Interception X3 server for UAG LI testing. This server can be used to decode and analysis received X3 message on both TCP and UDP. IPv4/IPv6/UDP/RTP/RTCP/DTMF info can be obtained from x3 package and a lot of check points are executed for verification.
For X3 over TCP: tcp segments are handle so no need to worry about incomplete or multiple X3 packages received in a single tcp segment.
For X3 over UDP: a separate cache thread is implemented to avoid package drop due to handling of heavy udp traffic. 
This server supports multiple targets monitoring.

[root@promote Lawful_Interception_x3_server]# ./li_server 


usage:

./li_server -l local_ip:local_port [optional options]

    -l : mandatory arguments, specify the local ip and port for listening x3, separated by ':'

    -T : timeout timer for socket recv if no pkg is received at all, in seconds, the default is 60s

    -t : timeout timer for socket recv if x3 pkg has been received, in seconds, the default is 2s

    -w : specify the outputed log file path and file name, the default is /tmp/li.log

    -f : specify the original pcap file to be compared with received x3

    -c : enable the IPv4 hdr checksum

    -d : dump the x3 msg body

Example:

    ./li_server -l 10.2.22.150:20000 -d

    or

    ./li_server -l 10.2.22.150:20000 -d -c -T 10 -w /root/my-li.log -f /root/srtp/rtp-rtcp.pcap


Result Sample:
./li_server -l 127.0.0.1:20000 -d

<10:44:31 DEBUG>[parse_x3(x3parser.cpp:49)] this is the 1 x3 package handled
<10:44:31 DEBUG>[parse_ip_hdr(x3parser.cpp:227)] src ip: 10.2.19.120, dst ip: 10.2.1.74
<10:44:31 DEBUG>[parse_udp_hdr(x3parser.cpp:238)] src port: 6188, dst port: 7078
<10:44:31 DEBUG>[parse_rtp(x3parser.cpp:295)] rtp sequence is 0, payload type is 8, SSRC is 0x7B47, rtp len 172
<10:44:31 DEBUG>[parse_x3(x3parser.cpp:69)] dump the received x3 data:
<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?>
<!DOCTYPE hi3-uag SYSTEM "hi3-uag.dtd">
<hi3-uag>
  <li-tid>31</li-tid>
  <stamp>2016-04-27 04:08:45</stamp>
  <CallDirection>from-target</CallDirection>
  <Correlation-id>1-12c-2-2-20386a</Correlation-id>
  <PayloadType>RTP</PayloadType>
  <PayloadLength>200</PayloadLength>
</hi3-uag>
450000c8000040003f1112600a0213780a02014a182c1ba600b4bce880080000000003c000007b47d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d555d5d5d5d5d5d5d5d5d555d5d5d5d5d55555d5d5d5d55555d5d5d5d55555d5d555d5d5555754d7d1d6d7d7d7d6d4565c5f51d4d0d3d0555f585d565656d1d8ded6d5d1d75651d4d0555f5850d0d9dfd6d5d5d55457515056d5d0dcd8d8d3515e52d4d1d5535e5f57d1d657535257d7d6565c50d6ddd65555d7d1d3dcd2d75456505d5c51


...............................................
=========================================================================================
x3 is over UDP
total X3 / errored X3 number: 7 / 0
targets number              : 4
correlation-id              : 1-12c-2-2-0386a
    type                    : X3_RTP
                              FROM              TO                SUM               
    X3_RTP NO.              : 0                 1                 1                 
    target / uag IP         : 2002:1890:1001:220b::32 / 2002:1890:1001:220b::32
    rtp target / uag port   : 8036 / 8042
        PT                  : 0
                              FROM              TO                SUM               
        RTP NO.             : 0                 1                 1                 
        SSRC                : 0x00000000        0x156D14CF          
        LossRate(%)         : 100.000           0.000             
        DTMF(2833)          : No                No                
correlation-id              : 1-12c-2-2-20386a
    type                    : X3_RTP
                              FROM              TO                SUM               
    X3_RTP NO.              : 2                 1                 3                 
    target / uag IP         : 10.2.19.120 / 10.2.1.74
    rtp target / uag port   : 6188 / 7078
        PT                  : 8
                              FROM              TO                SUM               
        RTP NO.             : 1                 1                 2                 
        SSRC                : 0x00007B47        0x0000251A          
        LossRate(%)         : 0.000             0.000             
        DTMF(2833)          : No                Yes               
    rtp target / uag port   : 6190 / 7080
        PT                  : 0
                              FROM              TO                SUM               
        RTP NO.             : 1                 0                 1                 
        SSRC                : 0x00007B47        0x00000000          
        LossRate(%)         : 0.000             100.000           
        DTMF(2833)          : No                No                
correlation-id              : 2-12c-2-2-0386a
    type                    : X3_MSRP
                              FROM              TO                SUM               
    X3_MSRP NO.             : 0                 1                 1                 

               /(|         
              (  :         
              _\  \  _____ 
           (____)  `|      
           (____)|  |      
           (____).__|      
            (___)__.|_____

=========================================================================================
