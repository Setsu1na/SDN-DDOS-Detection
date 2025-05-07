
import time
import os

import torch
import torch.nn as nn
import torch.nn.functional as F
import datetime
import scapy.all
import dpkt
from math import sqrt


# 时间存在问题！

# 其他变量
flows = [[{}, {}], [{}, {}], [{}, {}], [{}, {}]]  # 每个字典保存一台主机的流量统计信息,两个字典分别保存发出和接收的流量信息
flows_total = [{}, {}, {}, {}]  # 用于综合连接的整体信息（整合源到目的，与目的到源）
seq = 4
init = [0,0,0,0]
conn = False  # 三次握手的标志位
control_gate = [0, 0, 0, 0]  # 用于表示控制程度
packet_num = [0, 0, 0, 0]  # 用于记录连接通过的包数量
packet_information = [[[0] * 100 for _ in range(2)] for _ in range(4)]  # 每个字典保存一台主机的流量统计信息,两个字典分别保存数据包发出的时间戳和数据包的长度

access_control = 25  # 用于控制对于潜在攻击的敏感程度

features = ["Fwd Packet Length Max", "Fwd Packet Length Min", "Min Packet Length", "Max Packet Length",
            "Average Packet Size", "Fwd Packets/s", "Fwd Header Length", "Fwd Header Length.1", "min_seg_size_forward",
            "Total Length of Fwd Packets", "Fwd Packet Length Std", "Flow IAT Min", "Subflow Fwd Bytes", "Destination Port",
            "Protocol", "Packet Length Std", "Flow Duration", "Fwd IAT Total", "ACK Flag Count", "Init_Win_bytes_forward",
            "Flow IAT Mean", "Flow IAT Max", "Fwd IAT Mean", "Fwd IAT Max", "Label"]

attack_type = ['Normal', 'Portmap', 'LDAP', 'MSSQL', 'NetBIOS', 'Syn', 'UDP', 'UDPLag']

# reserve_1 用于记录三次握手相关信息，不是特征
http_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT']

# 进入后首先进行初始化。
for flow in flows:
    for i in range(2):
        for feature in features:
            flow[i][feature] = 0.0

"""各输入的具体形式暂不确定，目前以data代替"""

def init_pool():
    """用于初始化flow列表，初始化中并未初始化流特征相关项。"""
    global packet_num, packet_information, ack, dwin, head_len, mss, dport, protocol
    packet_information = [[[0] * 100 for _ in range(2)] for _ in range(4)]
    packet_num = [0,0,0,0]
    flows_total = [{}, {}, {}, {}]
    ack, dwin, head_len, mss, dport, protocol = 0,0,0,0,0,0
    print("初始化完毕")


def find_seq_id(src_ip, dst_ip):
    """本函数用于将内网中的ip号转换为id号，用于分主机处理"""
    """data应为源ip或目的ip，ip1~ip4为同一局域网中的4台测试主机"""
#    ip1 = "125.94.54.10"
    ip1 = "10.0.0.1"
    ip2 = "10.0.0.2"
    ip3 = "10.0.0.3"
    ip4 = "10.0.0.4"
    order = -1
    global init
    try:
        order = (ip1,ip2,ip3,ip4).index(src_ip)  # 找到主机号
        dst_num = 0  # 0代表从源发向目的，从子网主机发向服务器
        init[order] = 1
    except ValueError:
        order = (ip1, ip2, ip3, ip4).index(dst_ip)
        if init[order] == 0:  # 第一次发起连接
            dst_num = 0
            init[order] = 1
        else:  # 非第一次发起连接
            dst_num = 1  # 1代表从目的发向源，即从服务器发向子网主机
#    print(dst_num)
    return order, dst_num

def judge_services(trans_packet):
    """输入trans_packet为TCP报文，主要根据相关协议的端口号进行判断"""
    # 经过筛选支持http, ftp, ftp-data, smtp, pop3, dns, snmp, dhcp协议
    serv = 1  # 1为不知服务协议类型。
    method = None
    try:
        for feature in http_methods:
            if feature in trans_packet.payload.load.decode(encoding='utf-8'):  # 解码后为TCP负载的字符串
                serv = 2  # 2为http协议
                method = feature
                break
    except AttributeError:
        print("应用层无负载！")
    except UnicodeDecodeError:
        print("可能为加密传输！")
    # 判断http
    if trans_packet.dport == 443 or trans_packet.dport == 80 or trans_packet.sport == 80 or trans_packet.sport == 443:
        serv = 2

    # 判断ftp以及ftp-data
    if trans_packet.dport == 21 or trans_packet.sport == 21:
        serv = 3  # ftp
    elif trans_packet.sport == 20 or trans_packet.dport == 20:
        serv = 4  # ftp-data
    # 判断smtp&pop3
    if trans_packet.dport == 25 or trans_packet.dport == 465 or trans_packet.dport == 587:
        serv = 5  # smtp
    elif trans_packet.dport == 110:
        serv = 6  # pop3
    # 判断是否是dns&snmp协议
    if trans_packet.dport == 53:
        serv = 7  # dns udp
    elif trans_packet.dport == 161:
        serv = 8  # snmp
    # 判断是否是dhcp协议
    if trans_packet.dport == 67 or trans_packet.sport == 68:
        serv = 9  # dhcp
    elif trans_packet.sport == 67 or trans_packet.dport == 68:
        serv = 9  # dhcp
    # print("serv, method", serv, method, len(method))
    if serv != 2 and serv != 1:
        method = None
    return serv, method

def preprocess(num, dst_num, raw_packet, eth_packet, ip_packet, trans_packet, timestamp, judge):
    """
    用于预处理原始流量数据
    num为子网中的主机号，dst_num为流量方向，raw_packet为原始数据包，eth_packet为经过scapy的Ethernet封装后的数据包
    timestamp为时间戳信息
    """
    global conn  # 三次握手标志位
    start = -1  # 用于记录http的起始位置

    judge_service, method = judge_services(trans_packet)  # judge_service用于判断服务层协议，method用于得到http的方法
    try:
        service_data = trans_packet.payload.load.decode(encoding='utf-8')  # service_data为服务层的数据
    except AttributeError:
        service_data = ""
    except UnicodeDecodeError:
        service_data = trans_packet.payload

    if judge != 0:  # 对部分时间特征进行提取
        # 已建立连接
        flows[num][dst_num]['ltime'] = timestamp
    else:
        # 初次建立连接
        flows[num][dst_num]['stime'] = timestamp
        flows[num][dst_num]['ltime'] = timestamp + 1e-3
    # print(flows[num][dst_num]['stime'], flows[num][dst_num]['ltime'])
    flows[num][dst_num]['dur'] += flows[num][dst_num]['ltime']-flows[num][dst_num]['stime']
    if type(trans_packet) == scapy.all.TCP:
        flags = dpkt.ethernet.Ethernet(raw_packet).ip.tcp.flags
        # 用于记录三次握手相关信息 一般来说只在连接开始时进行
        if flags == 2:  # 检测到SYN连接
            # 初次检测到连接时，采用数据集的平均值填充
            conn = True
            flows[num][dst_num]['reserve_1'] = flows[num][dst_num]['ltime']
            flows[num][dst_num]['synack'] = 0.035986979
            flows[num][dst_num]['ackdat'] = 0.035823157
            flows[num][dst_num]['tcprtt'] = 0.071810136
        if conn == True and flags == 18:  # 检测SYN+ACK
            flows[num][dst_num]['synack'] = flows[num][dst_num]['ltime'] - flows[num][dst_num]['reserve_1']
            flows[num][dst_num]['reserve_1'] = flows[num][dst_num]['ltime']
            flows[num][dst_num]['ackdat'] = 0.035823157
            flows[num][dst_num]['tcprtt'] = flows[num][dst_num]['ackdat'] + flows[num][dst_num]['synack']
        if conn == True and flags == 16:  # 检测ACK
            conn = False
            flows[num][dst_num]['ackdat'] = flows[num][dst_num]['ltime'] - flows[num][dst_num]['reserve_1']
            flows[num][dst_num]['tcprtt'] = flows[num][dst_num]['ackdat'] + flows[num][dst_num]['synack']

    # 处理res_bdy_len特征
    if judge_service == 2:
        flows[num][dst_num]['res_bdy_len'] += len(trans_packet.payload)
        flows[num][dst_num]['ct_flw_http_mthd'] += 1
    elif judge_service == 1 and method != None:  # 请求头
        start = service_data.find(method)
        flows[num][dst_num]['res_bdy_len'] += len(service_data[start:-1])
        flows[num][dst_num]['ct_flw_http_mthd'] += 1
    elif judge_service == 1 and method == None:  # 响应头
        if 'HTTP/1.1' in service_data:
            start = service_data.find('HTTP/1.1')
        elif 'HTTP/1.2' in service_data:
            start = service_data.find('HTTP/1.2')
        elif 'HTTP/2' in service_data:
            start = service_data.find('HTTP/2')
        elif 'HTTP/1.0' in service_data:
            start = service_data.find('HTTP/1.0')
        flows[num][dst_num]['res_bdy_len'] += len(service_data[start:-1])
    # print("start:", start)
    flows[num][dst_num]['service'] = judge_service  # 应用层服务类型

    if dst_num == 0:  # 发送方统计信息
        flows[num][dst_num]['packet_num'] += 1
        flows[num][dst_num]['sbytes'] += len(raw_packet)
        flows[num][dst_num]['sload'] = flows[num][dst_num]['sbytes'] / flows[num][dst_num]['dur']
        flows[num][dst_num]['sttl'] = ip_packet.ttl
        flows[num][dst_num]['spkts'] += 1
        flows[num][dst_num]['smeansz'] = flows[num][dst_num]['sbytes'] / flows[num][dst_num]['packet_num']
        if flows[num][dst_num]['packet_num'] > 1:  # 如果有间隔
            flows[num][dst_num]['sintpkt'] = (timestamp - flows[num][dst_num]['stime'])/ (flows[num][dst_num]['packet_num'] - 1)
        else:
            flows[num][dst_num]['sintpkt'] = 0  # 如果没有间隔，即只有一个数据包
        if type(trans_packet) == scapy.all.TCP:  # TCP和UDP分开处理部分特征
            flows[num][dst_num]['swin'] = trans_packet.window
            if judge == 0:
                flows[num][dst_num]['stcpb'] = trans_packet.seq
        elif type(trans_packet) == scapy.all.UDP:    # 这段中的赋值可以删去
            flows[num][dst_num]['swin'] = 0.0
            flows[num][dst_num]['stcpb'] = 0.0
            flows[num][dst_num]['tcprtt'] = 0.0
            flows[num][dst_num]['synack'] = 0.0
            flows[num][dst_num]['ackdat'] = 0.0

    else:  # 接收方统计信息
        flows[num][dst_num]['packet_num'] += 1
        flows[num][dst_num]['dbytes'] += len(raw_packet)
        flows[num][dst_num]['dload'] = flows[num][dst_num]['dbytes'] / flows[num][dst_num]['dur']
        flows[num][dst_num]['dttl'] = ip_packet.ttl
        flows[num][dst_num]['dpkts'] += 1
        flows[num][dst_num]['dmeansz'] = flows[num][dst_num]['dbytes'] / flows[num][dst_num]['packet_num']
        if flows[num][dst_num]['packet_num'] > 1:  # 如果有间隔
            flows[num][dst_num]['dintpkt'] = (timestamp - flows[num][dst_num]['stime'])/ (flows[num][dst_num]['packet_num'] - 1)
        else:
            flows[num][dst_num]['dintpkt'] = 0  # 如果没有间隔，即只有一个数据包        # flows[num][dst_num]['res_bdy_len'] = 1
        if type(trans_packet) == scapy.all.TCP:  # TCP和UDP分开处理部分特征
            flows[num][dst_num]['dwin'] = trans_packet.window
            if judge == 0:
                flows[num][dst_num]['dtcpb'] = trans_packet.seq
        elif type(eth_packet.payload.payload) == scapy.all.UDP:  # 这段中的赋值可以删去
            flows[num][dst_num]['dwin'] = 0
            flows[num][dst_num]['dtcpb'] = 0
            flows[num][dst_num]['tcprtt'] = 0.0
            flows[num][dst_num]['synack'] = 0.0
            flows[num][dst_num]['ackdat'] = 0.0

def get_pred_data(num):
    pred_data = []
    for item in flows_total[num].values():
        pred_data.append(item)
    return pred_data


# 深度学习网络
class ConvNet_multi(nn.Module):
    # 用于构建多分类模型
    def __init__(self):
        super(ConvNet_multi, self).__init__()
        # class torch.nn.Conv1d(in_channels, out_channels, kernel_size,
        # stride=1, padding=0, dilation=1, groups=1, bias=True)
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3)
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.conv4 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.lstm1 = nn.LSTM(input_size=3, hidden_size=48, num_layers=2, batch_first=True) # 11/4
        self.gru1 = nn.GRU(input_size=11, hidden_size=48, num_layers=2, batch_first=True)
        # self.conv3 = nn.Conv1d(in_channels=128, out_channels=256, kernel_size=3)
        self.maxpool = nn.MaxPool1d(kernel_size=2, ceil_mode=True)
        self.avgpool = nn.AvgPool1d(kernel_size=2, ceil_mode=True)
        # 1 * 256 * x
        # self.fc1 = nn.Linear(6144, 1024) # with lstm
        self.fc1 = nn.Linear(3072, 128) # without lstm
        # self.fc2 = nn.Linear(1024, 2)
        # 用于多分类-8个类
        # self.fc2 = nn.Linear(1024, 7) # with lstm
        self.fc2 = nn.Linear(128, 8) # without lstm
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        in_size = x.size(0)
        out = self.conv1(x)
        # out = F.gelu(out) # 1, 64, 39
# #        out = self.maxpool(out)# 1, 64, 20
#         out = self.conv2(out)
#         out = F.gelu(out)
#         out = self.maxpool(out)
#         out = self.conv3(out)
#         out = F.gelu(out)
#         out = self.conv4(out)
#         # print(out.size)
#         out_size = out.size
#         out = F.gelu(out)
        out = self.maxpool(out)
        # out, (h, c) = self.lstm1(out) # 1, 64, 70
        out, h = self.gru1(out)
        # Flatten()
        out = out.contiguous().view(in_size, -1)

        out = F.dropout(out, p=0.25)
        out = self.fc1(out)
        out = F.gelu(out)
        out = F.dropout(out, p=0.5)
        out = self.fc2(out)
        out = F.gelu(out)
        out = self.softmax(out)
        return out

def data_assign(data, Device):
    print('------------------------------')
    # print(data)
    feature = torch.tensor(data, dtype=torch.float32)
    feature = feature.to(Device)
    return feature

# model = ConvNet().to(Device)
model = ConvNet_multi()
model_file = os.path.split(os.path.realpath(__file__))[0] + r'/dl-ids-multi2.pth'
model.load_state_dict(torch.load(model_file, map_location= 'cuda' if torch.cuda.is_available() else 'cpu')['net'])
Device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = model.to(Device)
# model.load_state_dict(torch.load(r'./dl-ids-multi2.pth')['net'])  # 引入之前训练好的神经网络


def predict(num):
    """用于预测流量的好坏"""
    data = get_pred_data(num)
    feature = data_assign(data, Device)
    feature.unsqueeze_(dim=0)
    feature.unsqueeze_(dim=0)
    model.eval()  # 开启测试模式
    print("准备进行分类！")
    output = model(feature)
    output = int(F.log_softmax(output, dim=1).max(1, keepdim=True)[1])
    if output == 0:
        # 正常流量
        print(datetime.datetime.now(), ":    正常流量。")
        return False, output
    else:
        # 攻击流量
        print(datetime.datetime.now(), ":    潜在DDOS攻击流量。")
        return True, output


def max(p):
    tmp = 0
    for i in p:
        if i>tmp:
            tmp = i
    return tmp

def min(p):
    tmp = 100000000
    for i in p:
        if i<tmp:
            tmp = i
    return tmp

def average(p):
    tmp = 0
    for i in p:
        tmp += i
    return tmp/len(p)

def standard_deviation(p):
    ave = average(p)
    tmp = 0
    for i in p:
        tmp += (i-ave) * (i-ave)
    return sqrt(tmp/len(p))

def min_segment(p):
    seg_min = 1e6
    for i in range(len(p)-1):
        tmp = p[i+1]-p[i]
        if seg_min>tmp:
            seg_min = tmp
    return  seg_min

def max_segment(p):
    seg_max = 0
    for i in range(len(p)-1):
        tmp = p[i+1]-p[i]
        if seg_max<tmp:
            seg_max = tmp
    return  seg_max


def get_input(data, timestamp):
    """
    用于读入数据
    目前ip，port等暂定，具体根据输入数据再进行改变。
    目前为一个主机一连接的形式
    """
    global packet_num, packet_information, ack, dwin, head_len, mss, dport, protocol
    raw_packet = scapy.all.raw(data)
    eth_packet = scapy.all.Ether(raw_packet)  # 将原始数据转换为底层的封装
    eth = dpkt.ethernet.Ethernet(raw_packet)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:  # 这里是对没有IP段的包过滤掉
        return -1
    print(eth_packet)
    sip = eth_packet.payload.src  # 源ip
    srport = eth_packet.payload.payload.sport  # 源端口
    dip = eth_packet.payload.dst  # 目的ip
    dport = eth_packet.payload.payload.dport  # 目的端口
    print("序号%d 进行连接：%s:%d-------->%s:%d" % (sum(packet_num),sip, srport, dip, dport))
    num,  dst_num= find_seq_id(eth_packet.payload.src, eth_packet.payload.dst)  # 得到主机号

    raw_packet = scapy.all.raw(data)
    # head_len = dpkt.ethernet.Ethernet(raw_packet).ip.ihl
    # if 'MSS' in dpkt.ethernet.Ethernet(raw_packet).ip.tcp.options:
    #     mss = dpkt.ethernet.Ethernet(raw_packet).ip.tcp.options.MSS
    # else:
    #     mss = 0

    Len = len(raw_packet)
    packet_information[num][0][packet_num[num]] = Len
    packet_information[num][1][packet_num[num]] = timestamp

    if type(eth_packet.payload.payload) == scapy.all.TCP:
        protocol = 6  # TCP协议
    elif type(eth_packet.payload.payload) == scapy.all.UDP:
        protocol = 17  # UDP协议
    else:
        return -3  # 协议类型不符合处理要求

    if num == -1:
        return -2
    # dst_num用于表示包的发送方向,0为从主机到服务器，1为从服务器到主机
    # num表示主机局域网中的主机序号

    if type(eth_packet.payload.payload) == scapy.all.TCP:
        ack = dpkt.ethernet.Ethernet(raw_packet).ip.tcp.ack
        dwin = eth_packet.payload.payload.window
    else:
        ack = 0
        dwin = 0

    return num

def extract(num):
    global ack, dwin, head_len, mss, dport, protocol
    flows_total[num]['Fwd Packet Length Max'] = max(packet_information[num][0])
    flows_total[num]['Fwd Packet Length Min'] = min(packet_information[num][0])

    tmp2 = []
    for i in range(4):
        tmp2.append(max(packet_information[i][0]))
    flows_total[num]['Min Packet Length'] = min(tmp2)
    tmp1 = []
    for i in range(4):
        tmp1.append(max(packet_information[i][0]))
    flows_total[num]['Max Packet Length'] = max(tmp1)

    tmp3 = []
    for i in range(4):
        tmp3.append(average(packet_information[i][0]))
    flows_total[num]['Average Packet Size'] = average(tmp3)

    flows_total[num]['Fwd Packets/s'] = average(packet_information[num][0]) * packet_num[num]/(packet_information[num][1][-1]-packet_information[num][1][0])

    flows_total[num]['Fwd Header Length'] = 64       #head_len * 4
    flows_total[num]['Fwd Header Length.1'] = 64      # head_len * 4

    flows_total[num]['min_seg_size_forward'] = 20                     # mss

    flows_total[num]['Total Length of Fwd Packets'] = packet_num[num]

    flows_total[num]['Fwd Packet Length Std'] = standard_deviation(packet_information[num][0])

    tmp4 = []
    for i in range(4):
        tmp4.append(min_segment(packet_information[i][0]))
    flows_total[num]['Flow IAT Min'] = min(tmp4)

    flows_total[num]['Subflow Fwd Bytes'] = packet_num[num]

    flows_total[num]['Destination Port'] = dport
    flows_total[num]['Protocol'] = protocol

    ave = flows_total[num]['Average Packet Size']
    tmp5 = 0
    for i in range(4):
        for a in packet_information[i][0]:
            tmp5 += (ave-a) * (ave-a)
    flows_total[num]['Packet Length Std'] = tmp5/sum(packet_num)

    tmp6 = packet_information[3][1][0]
    for i in range(3):
        if tmp6 < packet_information[i][1][0]:
            tmp6 = packet_information[i][1][0]
    flows_total[num]['Flow Duration'] = packet_information[num][1][-1] - tmp6
    flows_total[num]['Fwd IAT Total'] = packet_information[num][1][-3] - packet_information[num][1][-1]

    flows_total[num]['ACK Flag Count'] = ack

    flows_total[num]['Init_Win_bytes_forward'] = dwin

    flows_total[num]['Flow IAT Mean'] = (packet_information[num][1][-1]-tmp6)/(sum(packet_num)-1)

    tmp7 = []
    for i in range(4):
        tmp7.append(max_segment(packet_information[i][0]))
    flows_total[num]['Flow IAT Max'] = max(tmp7)

    flows_total[num]['Fwd IAT Mean'] = (packet_information[num][1][-1]-packet_information[num][1][0])/(packet_num[num]-1)
    flows_total[num]['Fwd IAT Max'] = max_segment(packet_information[num][0])

def IDS(data, *args):
    """data 为原始包数据， args[0]为时间戳数据"""
    global packet_num
    global packet_information
    num = get_input(data, args[0])

    packet_num[num] = packet_num[num] + 1
    print(packet_num[num])
    if sum(packet_num) >= 90:
        extract(num)
        tmp, output = predict(num)
        packet_num[num] += 1
        if tmp:
            # 用于处理发生攻击时的操作
            control_gate[num] += 1
            if control_gate[num] > access_control:
                print("当前连接安全性计数为:%d, 通过的数据包数量为:%d" % (control_gate[num], packet_num[num]))
                #  print("异常包占比:%f%%" % (100. * control_gate[num] / packet_num[num]))
                print("判定为： %s攻击" % (attack_type[output]))
                print('------------------------------')
                return attack_type[output]
            else:
                print("当前连接安全性计数为:%d, 通过的数据包数量为:%d" % (control_gate[num], packet_num[num]))
                #  print("异常包占比:%f%%" % (100. * control_gate[num] / packet_num[num]))
                print("判定为： 安全")
                print('------------------------------')
                return 'Normal'
        else:
            # 用于处理了未发生攻击时的操作
            print("当前连接安全性计数为:%d, 通过的数据包数量为:%d" % (control_gate[num], packet_num[num]))
            #  print("异常包占比:%f%%" % (100. * control_gate[num] / packet_num[num]))
            print("判定为： 安全")

            print('------------------------------')
            return 'Normal'
        init_pool()
    return 'Normal'

if __name__ == '__main__':
    for i in range(100):
        a = scapy.all.Ether() / scapy.all.IP(dst="192.168.3.2", src="10.0.0.1") / scapy.all.TCP(sport=1234, dport=80) / "GET /index.html HTTP/1.0 \n\n"
        IDS(a, a.time)
        # time.sleep(1)

