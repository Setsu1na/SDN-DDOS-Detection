from scapy.all import *
import socket
#import fcntl
pcap_file = "./test1.pcap"  # 此处修改测试的用例
# test1-safe.pcap test2-dos.pcap test2-dos2.pcap test-safe.pcap
#pcap_file = r"D:\dataset\UNSW-NB15\test1-safe.pcap"

'''
def get_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #return socket.inet_ntoa(fcntl.ioctl(s.fileno(),
                                        0x8915,
                                        struct.pack("256s", iface[:15]))[20:24])
'''

def dispatch():
    pkts = rdpcap(pcap_file)
    tmp1 = "10.0.0.2"
    tmp2 = "192.168.3.2"  # 填入本机地址
    tmp_src_ip = "0.0.0.0"
    tmp_dst_ip = "1.1.1.1"
    n = 0
    for i in range(len(pkts)):
        pkt = pkts[i]
        #pkt[Ether].src = "00:00:00:00:00:02"
        #pkt[Ether].dst = "00:00:00:00:00:02"
        #  下面的调整用于更符合收发包的地址变换
        if n == 0:
            tmp_src_ip = pkt[IP].src
            tmp_dst_ip = pkt[IP].dst
            pkt[IP].src = tmp1
            pkt[IP].dst = tmp2
            n = 1
        else:
            if tmp_src_ip != pkt[IP].src or tmp_dst_ip != pkt[IP].dst:
                tmp_src_ip = pkt[IP].src
                tmp_dst_ip = pkt[IP].dst
                tmp = tmp1
                tmp1 = tmp2
                tmp2 = tmp
                pkt[IP].src = tmp1
                pkt[IP].dst = tmp2
            else:
                pkt[IP].src = tmp1
                pkt[IP].dst = tmp2

        # reset to recalculate
        pkt[IP].len = None
        pkt[IP].checksum = None
        pkt[TCP].len = None
        pkt[TCP].checksum = None
        print(pkt)
        print('-------------------')
        sendp(pkt)


if __name__ == '__main__':
    dispatch()
