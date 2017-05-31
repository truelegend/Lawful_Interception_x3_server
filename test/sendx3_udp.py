import socket
import binascii
import time
server_addr = ('127.0.0.1',20000)
client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

hdr1 = b'''<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?><!DOCTYPE hi3-uag SYSTEM "hi3-uag.dtd"><hi3-uag><li-tid>31</li-tid><stamp>2016-04-27 04:08:45</stamp><CallDirection>to-target</CallDirection><Correlation-id>1-12c-2-2-20386a</Correlation-id><PayloadType>RTP</PayloadType><PayloadLength>200</PayloadLength></hi3-uag>'''
ip1 = binascii.a2b_hex(b"450000c8000040003f1112600a0213780a02014a")
udp1 = binascii.a2b_hex(b"182c1ba600b4bce8")
rtp1 = binascii.a2b_hex(b"80080000000003c000007b47d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d555d5d5d5d5d5d5d5d5d555d5d5d5d5d55555d5d5d5d55555d5d5d5d55555d5d555d5d5555754d7d1d6d7d7d7d6d4565c5f51d4d0d3d0555f585d565656d1d8ded6d5d1d75651d4d0555f5850d0d9dfd6d5d5d55457515056d5d0dcd8d8d3515e52d4d1d5535e5f57d1d657535257d7d6565c50d6ddd65555d7d1d3dcd2d75456505d5c51")

body1 = ip1 + udp1 + rtp1

x31 = hdr1 + body1
client.sendto(x31,server_addr)

time.sleep(0.02)
#body2 = binascii.a2b_hex(b"450000c8013f40006f11df92dfd63f310a02014a641e271200b4000080084388067f97744cb7239ad5d55555d555555555d5d5d555d5d5d5d55555d5d55555d55555d5d5d555d55555d5d555d55555d555d55555d5d5d5d5d555d555d555d5d55555555555555555d5d555d555d5d55555d555d5d5d5555555d555555555d5d5d555d5d555d55555d555d555d5d5d5d5d5d55555555555d555d5d555d5d5d555d55555d55555d5d5d555d5d5d5d5555555d5d5d5d5d5d5d5d555d5555555d5d5d5d555555555d5d5")
#x3 = hdr + body2
#client.sendto(x3,server_addr)

hdr2 = b'''<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?><!DOCTYPE hi3-uag SYSTEM "hi3-uag.dtd"><hi3-uag><li-tid>31</li-tid><stamp>2016-04-27 04:08:45</stamp><CallDirection>from-target</CallDirection><Correlation-id>1-12c-33-2-20386a</Correlation-id><PayloadType>RTP</PayloadType><PayloadLength>200</PayloadLength></hi3-uag>'''
x32 = hdr2 + body1
client.sendto(x32,server_addr)


time.sleep(0.02)

hdr3 = b'''<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?><!DOCTYPE hi3-uag SYSTEM "hi3-uag.dtd"><hi3-uag><li-tid>31</li-tid><stamp>2016-04-27 04:08:45</stamp><CallDirection>to-target</CallDirection><Correlation-id>1-12c-33-2-20386a</Correlation-id><PayloadType>RTP</PayloadType><PayloadLength>168</PayloadLength></hi3-uag>'''

ip_rtcp = binascii.a2b_hex(b"450000a81d3f00008011f4400a02014a0a021378")
udp_rtcp = binascii.a2b_hex(b"1ba7182d009493be")
rtcp = binascii.a2b_hex(b"81c8000c0000251ad545a258a7bc3c5b00004ec00000007c00004d8000007b47000000000000007b0000009f000000000000000081ca00150000251a011e7369703a31343430383731303034394031302e322e312e37343a35303631060e4c696e70686f6e652d332e352e32071d54686973206973206672656520736f667477617265202847504c29202100")

x3_rtcp = hdr3 + ip_rtcp + udp_rtcp + rtcp

client.sendto(x3_rtcp,server_addr)


time.sleep(0.02)
hdr4 = b'''<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?><!DOCTYPE hi3-uag SYSTEM "hi3-uag.dtd"><hi3-uag><li-tid>31</li-tid><stamp>2016-04-27 04:08:45</stamp><CallDirection>to-target</CallDirection><Correlation-id>1-12c-2-2-0386a</Correlation-id><PayloadType>RTP</PayloadType><PayloadLength>220</PayloadLength></hi3-uag>'''
ip_v6 = binascii.a2b_hex(b"6000000000b41140200218901001220b0000000000000032200218901001220b0000000000000032")
udp4= binascii.a2b_hex(b"1f6a1f6400b45c71")
rtp4 = binascii.a2b_hex(b"8000000000000320156d14cfffffffffffffffff7fff7fff7fffff7ffe7efe7efe7efefe7bdfdbe1ef6a5e4e4e4f4e636366e2f97c6e585a575c5c5e68555d5e596e635f605b5a585755575c585e60555c595956585f565b5c5653585a565b595b5f54525653595c615c6568565e55525e5c635d685d5663555a5c595e5b5d595a5d585f6661625b595a5b5859605d606460635c655f5b61595b5f5d605f635c595e5e65636262615f5c5e5e")

x3_rtp_ipv6 = hdr4 + ip_v6 + udp4 + rtp4
client.sendto(x3_rtp_ipv6,server_addr)

time.sleep(0.02)
hdr_msrp = b'''<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?><!DOCTYPE hi3-uag SYSTEM "hi3-uag.dtd"><hi3-uag><li-tid>31</li-tid><stamp>2016-04-27 04:08:45</stamp><CallDirection>to-target</CallDirection><Correlation-id>2-12c-2-2-0386a</Correlation-id><PayloadType>MSRP</PayloadType><PayloadLength>6</PayloadLength></hi3-uag>'''
#ip4 = binascii.a2b_hex(b"6000000000b41140200218901001220b0000000000000032200218901001220b0000000000000032")
#udp4= binascii.a2b_hex(b"1f6a1f6400b45c71")
#rtp4 = binascii.a2b_hex(b"8000000000000320156d14cfffffffffffffffff7fff7fff7fffff7ffe7efe7efe7efefe7bdfdbe1ef6a5e4e4e4f4e636366e2f97c6e585a575c5c5e68555d5e596e635f605b5a585755575c585e60555c595956585f565b5c5653585a565b595b5f54525653595c615c6568565e55525e5c635d685d5663555a5c595e5b5d595a5d585f6661625b595a5b5859605d606460635c655f5b61595b5f5d605f635c595e5e65636262615f5c5e5e")
msrp = b"abcdef"
x3_msrp = hdr_msrp + msrp
client.sendto(x3_msrp,server_addr)



client.close()
