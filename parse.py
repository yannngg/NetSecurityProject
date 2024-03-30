# from queue import Queue
from socket import *
from struct import *
import time
import threading


class parse_thread(threading.Thread):
    """ 自定义解析线程类，相比于threading增加了pause、resume、stop的功能
    并且对run函数做了修改，run会循环执行，每次解析一个数据包，无数据包时会空转
    """
    def __init__(self, packet_queue, filter_id, filter_str):
        super(parse_thread, self).__init__()
        # 待解析的包队列(每个元素是类型、包、时间的三元组)
        self.packet_wait_parse_queue = packet_queue
        # filter过滤器的id
        self.filter_id = filter_id
        # filter过滤器中的表达式
        self.filter_str = filter_str

        # 捕获到的包队列(每个元素是一个完整的数据包)
        self.packet_list = list()
        # 数据包头队列（每个元素是一个json格式数据，保存一个包的头部信息）
        self.packet_head = list()
        # 提取到的重要信息（每个元素也是一个list，依次为序号 时间 源地址 源端口 目的地址 目的端口 协议类型）
        self.packet_info = list()
        # 记录每个数据包的时间戳
        self.packet_time = list()
        # 记录包的序号，从1开始（不是从0开始）
        self.packet_index = 0
        # 下一个被GUI调用显示出来的包的索引
        self.packet_display_index = 0

        self.dns_stream = list()
        self.dns_stream_index = 0

        self.__flag = threading.Event()     # 用于暂停线程的标识
        self.__flag.set()       # 设置为True
        self.__running = threading.Event()      # 用于停止线程的标识
        self.__running.set()      # 将running设置为True

    def run(self):
        while self.__running.isSet():
            self.__flag.wait()      # 为True时立即返回, 为False时阻塞直到内部的标识位为True后返回
            if self.packet_wait_parse_queue.empty():
                continue
            # pkt_time的时间格式为Unix时间戳
            l2_type, l2_packet, pkt_time = self.packet_wait_parse_queue.get()
            time_high = int(pkt_time)
            time_low = pkt_time - time_high
            time_low = int(str(time_low)[2:8])
            self.packet_index += 1

            info = new_a_info()
            info['num'] = str(self.packet_index)
            info['time'] = time.strftime("%Y年%m月%d日 %H:%M:%S", time.localtime(time_high))
            # info['time'] += '.' + str(time_low).ljust(9, '0')
            # 解析数据包，获取各层协议的包头信息，保存在packet_head_json中
            packet_head_json = {}
            info, packet_head_json, self.dns_stream, self.dns_stream_index = \
                parse_a_packet(l2_packet, info, packet_head_json, self.dns_stream, self.dns_stream_index)

            if filter_packet(self.filter_id, packet_head_json, info, self.filter_str):
                # 保留当前包
                self.packet_list.append(l2_packet)
                self.packet_time.append((time_high, time_low))
                self.packet_info.append(info)
                self.packet_head.append(packet_head_json)
            else:
                # 过滤掉当前包
                self.packet_index -= 1

    def pause(self):
        """ 线程暂停 """
        self.__flag.clear()     # 设置为False, 让线程阻塞

    def resume(self):
        """ 线程继续运行 """
        self.__flag.set()    # 设置为True, 让线程停止阻塞

    def stop(self):
        """ 线程退出 """
        self.__flag.set()       # 将线程从暂停状态恢复, 如何已经暂停的话
        self.__running.clear()        # 设置为False


"""
B   8bit
H   16bit
I   32bit
"""


def filter_packet(filter_id, packet_head_json, packet_info, filter_str):
    """根据传入的filter_id确定是否保留数据包，保留则返回True，丢弃数据包则返回False"""

    # 去除所有空格
    filter_str = filter_str.replace(' ', '').split('==')
    # 不过滤
    if filter_id <= 0:
        return True
    elif filter_id == 1:
        # 保留tcp数据包
        for layer, info in packet_head_json.items():
            if layer == 'Transmission Control Protocol':
                return True
        return False
    elif filter_id == 2:
        # 保留udp数据包
        for layer, info in packet_head_json.items():
            if layer == 'User Datagram Protocol':
                return True
        return False
    elif filter_id == 3:
        # ip==1.1.1.1
        for layer, info in packet_head_json.items():
            if layer == 'Internet Protocol Version 4':
                if filter_str[1] == info.get('Source_Address', '') or \
                   filter_str[1] == info.get('Destination_Address', ''):
                    return True
        return False
    elif filter_id == 4:
        # port==12
        for layer, info in packet_head_json.items():
            if layer == 'User Datagram Protocol' or layer == 'Transmission Control Protocol':
                if filter_str[1] == str(info.get('Source_Port', '')) or \
                   filter_str[1] == str(info.get('Destination_Port', '')):
                    return True
        return False
    elif filter_id == 5:
        # src.ip==1.1.1.1
        for layer, info in packet_head_json.items():
            if layer == 'Internet Protocol Version 4':
                if filter_str[1] == info.get('Source_Address', ''):
                    return True
        return False
    elif filter_id == 6:
        # dst.ip==1.1.1.1
        for layer, info in packet_head_json.items():
            if layer == 'Internet Protocol Version 4':
                if filter_str[1] == info.get('Destination_Address', ''):
                    return True
        return False
    elif filter_id == 7:
        # src.port==12
        for layer, info in packet_head_json.items():
            if layer == 'User Datagram Protocol' or layer == 'Transmission Control Protocol':
                if filter_str[1] == str(info.get('Source_Port', '')):
                    return True
        return False
    elif filter_id == 8:
        # dst.port==12
        for layer, info in packet_head_json.items():
            if layer == 'User Datagram Protocol' or layer == 'Transmission Control Protocol':
                if filter_str[1] == str(info.get('Destination_Port', '')):
                    return True
        return False
    elif filter_id == 9:
        # tcp.port==12
        for layer, info in packet_head_json.items():
            if layer == 'Transmission Control Protocol':
                if filter_str[1] == str(info.get('Source_Port', '')) or \
                   filter_str[1] == str(info.get('Destination_Port', '')):
                    return True
        return False
    elif filter_id == 10:
        # udp.port==12
        for layer, info in packet_head_json.items():
            if layer == 'User Datagram Protocol':
                if filter_str[1] == str(info.get('Source_Port', '')) or \
                   filter_str[1] == str(info.get('Destination_Port', '')):
                    return True
        return False
    # TODO 11 12 关于 stream，暂未实现
    elif filter_id == 13:
        # dns
        return packet_info['type'] == 'DNS'
    else:
        return True


def new_a_info():
    """创建一个info的字典，其中记录一个包的重要信息，如源和目的地址和端口等"""
    info = {'num': '-1',
            'time': '-1',
            'src_addr': '0',
            'src_port': '-',
            'dst_addr': '0',
            'dst_port': '-',
            'type': '-',
            'dns_stream': '-',
            # 'tcp_stream': '-'
            }
    return info


def parse_pcap_file(filename):
    """解析pcap文件
    :returns: pcap_header, packet_time, packet_list, packet_info, packet_head
    """
    packet_time = list()
    packet_list = list()
    packet_info = list()
    packet_head = list()
    packet_index = 1

    dns_stream = list()
    dns_stream_index = 0

    pcap = open(filename, 'rb')
    # 读取pcap文件头的24字节
    pcap_header = pcap.read(24)

    # 读取包头的16字节
    pkt_header = pcap.read(16)
    while pkt_header != b'':
        time_high, time_low, cap_len, pkt_len = unpack("<IIII", pkt_header)
        l2_packet = pcap.read(pkt_len)
        if l2_packet == '':
            break

        info = new_a_info()
        info['num'] = str(packet_index)
        info['time'] = time.strftime("%Y年%m月%d日 %H:%M:%S", time.localtime(time_high))
        # info['time'] += '.' + str(time_low).ljust(9, '0')

        packet_head_json = {}
        info, packet_head_json, dns_stream, dns_stream_index = \
            parse_a_packet(l2_packet, info, packet_head_json, dns_stream, dns_stream_index)

        packet_time.append((time_high, time_low))
        packet_list.append(l2_packet)
        packet_info.append(info)
        packet_head.append(packet_head_json)
        packet_index += 1
        # 读取包头的16字节
        pkt_header = pcap.read(16)

    pcap.close()

    return pcap_header, packet_time, packet_list, packet_info, packet_head

# 传输层协议及其协议号
Transport_Layer_Protocol = {
    '1'  : 'ICMP',
    '2'  : 'IGMP',
    '6'  : 'TCP',
    '17' : 'UDP',
    '47' : 'GRE',
    '50' : 'ESP',
    '51' : 'AH',
    '58' : 'ICMPv6',
    '88' : 'EIGRP',
    '89' : 'OSPF',
    '112': 'VRRP',
    '115': 'L2TP',
}

"type字段标识为 0x86dd，表示承载的上层协议是IPv6，IPv4对比：type字段为0x0800"
def parse_a_packet(packet, info, packet_head_json, dns_stream, dns_stream_index):
    """ 解析一个数据包，最后返回info和json
    """
    
    # 解析数据包的链路层
    ip_packet, eth_header = parse_eth(packet)

    info['src_addr'] = eth_header['Source']
    info['dst_addr'] = eth_header['Destination']
    info['type'] = 'Ethernet'
    packet_head_json['Ethernet'] = eth_header

    if eth_header['Type'] == '0x0800':
        trans_packet, ip_header = parse_ipv4(ip_packet)
        info['src_addr'] = ip_header['Source_Address']
        info['dst_addr'] = ip_header['Destination_Address']
        info['type'] = ip_header['Protocol']
        packet_head_json['Internet Protocol Version 4'] = ip_header
        
        info, packet_head_json, dns_stream = \
            parse_trans(trans_packet, info, ip_header, packet_head_json, dns_stream, dns_stream_index)

    elif eth_header['Type'] == '0x0806':
        arp_header = parse_arp(ip_packet)
        info['type'] = 'ARP'
        packet_head_json['ARP'] = arp_header

    elif eth_header['Type'] == '0x86dd':
        trans_packet, ip_header = parse_ipv6(ip_packet)
        info['type'] = Transport_Layer_Protocol[ip_header['Protocol']]
        info['src_addr'] = ip_header['Source_Address']
        info['dst_addr'] = ip_header['Destination_Address']
        packet_head_json['Internet Protocol Version 6'] = ip_header
        # 对ipv6 数据报进行解析
        info, packet_head_json, dns_stream = \
            parse_trans(trans_packet, info, ip_header, packet_head_json, dns_stream, dns_stream_index)
        

    elif eth_header['Type'] == '0x8864':
        print("链路层无法识别[PPPoE]协议")
    elif eth_header['Type'] == '0x8100':
        print("链路层无法识别[802.1Q tag]协议")
    elif eth_header['Type'] == '0x8847':
        print("链路层无法识别[MPLS Label]协议")
    else:
        # unknown ip protocol
        print("链路层无法识别")

    return info, packet_head_json, dns_stream, dns_stream_index


# 解析传输层
def parse_trans(trans_packet, info, ip_header, packet_head_json, dns_stream, dns_stream_index):
    if ip_header['Protocol'] == '6':
        # 解析tcp
        app_packet, tcp_header = parse_tcp(trans_packet)
        info['src_port'] = tcp_header['Source_Port']
        info['dst_port'] = tcp_header['Destination_Port']
        info['type'] = 'TCP'
        packet_head_json['Transmission Control Protocol'] = tcp_header
        
        # 解析应用层
        info, packet_head_json = parse_app(app_packet, info, packet_head_json)

    elif ip_header['Protocol'] == '17':
        # 解析udp
        app_packet, udp_header = parse_udp(trans_packet)
        info['src_port'] = udp_header['Source_Port']
        info['dst_port'] = udp_header['Destination_Port']
        info['type'] = 'UDP'
        packet_head_json['User Datagram Protocol'] = udp_header

        if info['dst_port'] == '53':
            # 发送DNS请求
            # 格式：流序号-本机端口号-dns服务器ip
            dns_stream.append(str(dns_stream_index) + '-' + info['src_port'] + '-' + info['dst_addr'])
            info['dns_stream'] = dns_stream_index
            info['type'] = 'DNS'
            dns_stream_index += 1
        if info['src_port'] == '53':
            # 收到DNS应答
            for item in dns_stream:
                index, port, ip = item.split('-')
                if port == info['dst_port'] and ip == info['src_addr']:
                    info['dns_stream'] = index
                    info['type'] = 'DNS'
                    dns_stream.remove(item)
                    break
        # 解析应用层
        info, packet_head_json = parse_app(app_packet, info, packet_head_json)

    elif ip_header['Protocol'] == '1':
        # 解析icmp
        icmp_header = parse_icmp(trans_packet)
        info['type'] = 'ICMP'
        packet_head_json['ICMP'] = icmp_header
        
    elif ip_header['Protocol'] == '58':
        icmpv6_header = parse_icmpv6(trans_packet)
        info['type'] = 'ICMPv6'
        packet_head_json['ICMPv6'] = icmpv6_header
        
    else:
        info['type'] = Transport_Layer_Protocol[ip_header['Protocol']]
        
    return info, packet_head_json, dns_stream

# 解析应用层协议，简单通过端口来确定应用层协议
def parse_app(app_packet, info, packet_head_json):
    if info['src_port'] == '80' or info['dst_port'] == '80':
        info['type'] = 'HTTP'
        http_header = parse_http(app_packet, info)
        packet_head_json['HyperText Transfer Protocol'] = http_header
        
    elif info['src_port'] == '53' or info['dst_port'] == '53':
        info['type'] = 'DNS'
        dns_header = parse_dns(app_packet)
        packet_head_json['Domain Name System'] = dns_header
    
    elif info['src_port'] == '20' or info['dst_port'] == '20' \
        or info['src_port'] == '21' or info['dst_port'] == '21':
        info['type'] = 'FTP'
        ftp_header = parse_ftp(app_packet)
        packet_head_json['File Transfer Protocol'] = ftp_header

    elif info['src_port'] == '22' or info['dst_port'] == '22':
        info['type'] = 'SSH'
        ssh_header = parse_ssh(app_packet)
        packet_head_json['Secure Shell'] = ssh_header
    
    elif info['src_port'] == '23' or info['dst_port'] == '23':
        info['type'] = 'TELNET'
        
    return info, packet_head_json
    

def bytes2mac_addr(addr):
    """将字节流转为MAC地址字符串"""
    return ":".join("%02x" % i for i in addr)


def bytes2uint(data):
    """将字节流转为大尾端无符号整数"""
    return int.from_bytes(data, byteorder='big', signed=False)


def parse_eth(packet):
    """解析链路层头部
    :return: 网络层的数据包和解析过的链路层头部（包含源、目的MAC地址，网络层协议类型）
    """
    # 获取头部字节流
    # ！表示网络序，s表示一个字节
    eth_header = list(unpack("!6s6sH", packet[:14]))
    res = {}
    # 转为可读的MAC地址
    # 目的
    res['Destination'] = bytes2mac_addr(eth_header[0])
    # eth_header[0] = bytes2mac_addr(eth_header[0])
    # 源
    res['Source'] = bytes2mac_addr(eth_header[1])
    # eth_header[1] = bytes2mac_addr(eth_header[1])
    # 转为十六进制的下一层协议类型，需要是字符串
    res['Type'] = "".join("0x%04x" % eth_header[2])
    # eth_header[2] = "".join("0x%04x" % eth_header[2])
    return packet[14:], res


def parse_ipv4(packet):
    """解析网络层头部，类型为ipv4
    :return: 传输层数据包和字典形式的ip层头部信息
    """
    header_info = unpack("!BBHHHBBH4s4s", packet[:20])

    ip_header = {}
    ip_header['Version'] = header_info[0] >> 4
    # 单位是4Bytes
    ip_header['Header_Length'] = header_info[0] & 0x0f
    ip_header['Differentiated_Services_Field'] = header_info[1]
    # 单位是Byte，包括ip头部和数据部分长度
    ip_header['Total_Length'] = header_info[2]
    ip_header['Identification'] = header_info[3]
    ip_header['Flags'] = header_info[4] >> 13
    ip_header['Fragment_Offset'] = header_info[4] & 0x1fff
    ip_header['Time_to_Live'] = header_info[5]
    ip_header['Protocol'] = str(header_info[6])
    ip_header['Header_Checksum'] = header_info[7]
    ip_header['Source_Address'] = inet_ntoa(header_info[8])
    ip_header['Destination_Address'] = inet_ntoa(header_info[9])
    # 头部没有Option可选部分
    if ip_header['Header_Length'] == 5:
        # 返回下一层数据包和ip头部信息
        return packet[20:], ip_header
    else:
        # TODO 解析Option可选字段
        option = packet[20:ip_header['Header_Length'] * 4]
        return packet[ip_header['Header_Length'] * 4:], ip_header


def parse_ipv6(packet):
    """解析网络层头部，类型为ipv6
    :return: 传输层数据包和字典形式的ip层头部信息
    """
    header_info = unpack("!IHBB16s16s", packet[:40])

    ip_header = {}
    ip_header['Version'] = header_info[0] >> 28
    ip_header['Traffic_Class'] = (header_info[0] >> 20) & 0x0ff
    ip_header['Flow_Label'] = header_info[0] & 0xfffff
    # 单位为字节，包括了ipv6扩展头部
    ip_header['Payload_Length'] = header_info[1]
    ip_header['Next_Header'] = str(header_info[2])
    # ttl
    ip_header['Hop_Limit'] = header_info[3]
    ip_header['Source_Address'] = inet_ntop(AF_INET6, header_info[4])
    ip_header['Destination_Address'] = inet_ntop(AF_INET6, header_info[5])

    if ip_header['Next_Header'] in Transport_Layer_Protocol.keys():
        # 直接识别传输层协议
        ip_header['Protocol'] = ip_header['Next_Header']
    else:
        ptr = 40
        # 解析出下一首部和首部长度
        NH_HL = unpack("!BB", packet[ptr:ptr+2])
        while (str(NH_HL[0]) not in Transport_Layer_Protocol.keys()):
            ptr = ptr + 2 + NH_HL[1]
            NH_HL = unpack("!BB", packet[ptr:ptr+2])
        
        ip_header['Protocol'] = str(NH_HL[0])
        return packet[ptr:], ip_header

    return packet[40:], ip_header


def parse_tcp(packet):
    """解析传输层头部，类型为tcp
    :return: 传输层payload，字典形式的tcp层头部信息
    """
  
    header_info = unpack("!HHIIHHHH", packet[:20])

    tcp_header = {}
    tcp_header['Source_Port'] = str(header_info[0])
    tcp_header['Destination_Port'] = str(header_info[1])
    tcp_header['Sequence_Number'] = header_info[2]
    tcp_header['Acknowledgement_Number'] = header_info[3]
    # 单位是4Bytes
    tcp_header['Header_Length'] = header_info[4] >> 12
    tcp_header['Flags'] = header_info[4] & 0xfff
    tcp_header['Window'] = header_info[5]
    tcp_header['Checksum'] = header_info[6]
    tcp_header['Urgent_Pointer'] = header_info[7]

    # 头部没有Option可选部分
    if tcp_header['Header_Length'] == 5:
        # 返回下一层数据包和tcp头部信息
        return packet[20:], tcp_header
    else:
        # TODO 解析Option可选字段
        option = packet[20:tcp_header['Header_Length'] * 4]
        return packet[tcp_header['Header_Length'] * 4:], tcp_header


def parse_udp(packet):
    """解析传输层头部，类型为udp
    :return: 传输层的payload，字典形式的udp层头部信息
    """
    header_info = unpack("!HHHH", packet[:8])

    udp_header = {}
    udp_header['Source_Port'] = str(header_info[0])
    udp_header['Destination_Port'] = str(header_info[1])
    udp_header['Length'] = header_info[2]
    udp_header['Checksum'] = header_info[3]

    return packet[8:], udp_header



def parse_icmp(packet):
    """解析icmp头部，其位于ip头部的后面
    :return: 字典形式的icmp头部信息
    """
    header_info = unpack("!BBHHH", packet[:8])

    icmp_header = {}
    icmp_header['Type'] = header_info[0]
    icmp_header['Code'] = header_info[1]
    icmp_header['Checksum'] = header_info[2]
    icmp_header['Identifier'] = header_info[3]
    icmp_header['Sequencu_Number'] = header_info[4]

    return icmp_header

def parse_icmpv6(packet):
    """解析icmpv6头部，其位于ipv6头部的后面
    :return: 字典形式的icmpv6头部信息
    """
    header_info = unpack("!BBHH", packet[:6])

    icmpv6_header = {}
    icmpv6_header['Type'] = header_info[0]
    icmpv6_header['Code'] = header_info[1]
    icmpv6_header['Checksum'] = header_info[2]
    icmpv6_header['Identifier'] = header_info[3]

    return icmpv6_header



def parse_arp(packet):
    """解析arp头部，其位于mac头部的后面
    :return: 字典形式的arp头部信息
    """
    header_info = unpack("!HHBBH", packet[:8])

    arp_header = {}
    h_type = header_info[0]
    p_type = header_info[1]
    h_size = header_info[2]
    p_size = header_info[3]
    arp_header['Hardware_type'] = h_type
    arp_header['Protocol_type'] = p_type
    arp_header['Hardware_size'] = h_size
    arp_header['Protocol_size'] = p_size
    arp_header['Opcode'] = header_info[4]

    form = "!"
    form += str(h_size) + "s"
    form += str(p_size) + "s"
    form += str(h_size) + "s"
    form += str(p_size) + "s"
    address = unpack(form, packet[8: 8 + (h_size + p_size) * 2])
    if h_type == 1 and p_type == 0x0800:
        # ethernet ipv4
        arp_header['Sender_Hard_address'] = bytes2mac_addr(address[0])
        arp_header['Sender_Prot_address'] = inet_ntoa(address[1])
        arp_header['Target_Hard_address'] = bytes2mac_addr(address[2])
        arp_header['Target_Prot_address'] = inet_ntoa(address[3])
    else:
        # 不确定链路层和ip层使用的协议类型
        arp_header['Sender_Hard_address'] = address[0]
        arp_header['Sender_Prot_address'] = address[1]
        arp_header['Target_Hard_address'] = address[2]
        arp_header['Target_Prot_address'] = address[3]

    return arp_header

# TODO: DNS FTP SMTP TLS HTTP
def parse_http(app_packet, info):
    http_header = {}
    # 解析http头部
    packet_line = app_packet.decode().split("\r\n")
    packet_line = [i.split(' ') for i in packet_line]
    
    
    # 一坨，但是有用
    if len(packet_line) > 1 and len(packet_line[0]) == 3:
        # 请求
        if info['dst_port'] == '80':
            http_header['Method'] = packet_line[0][0]
            http_header['URL'] = packet_line[0][1]
            http_header['Protocol'] = packet_line[0][2]
        elif info['src_port'] == '80':
            http_header['Protocol'] = packet_line[0][0]
            http_header['Status_Code'] = packet_line[0][1]
            http_header['Reason_Phrase'] = packet_line[0][2]
        
        # 添加首部字段
        for i in range(1, len(packet_line)):
            if ':' in packet_line[i][0]:
                value = ''
                for j in packet_line[i][1:]:
                    if ',' in j:
                        value += j
                    else:
                        value += j + ' '
                http_header[packet_line[i][0].strip(':')] = value
            
            elif len(packet_line[i]) == 1:
                data = ''
                if (i + 1) < len(packet_line):
                    data = ''
                    for j in packet_line[i+1:]:
                        for k in j:
                            data += k   
                http_header['Data'] = data
                break
        
        http_header['Body'] = app_packet[len(app_packet) - len(app_packet.decode()):]
        http_header['Size'] = len(app_packet)
        http_header['Time'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    return http_header

    

def parse_ftp(app_packet):
    ftp_header = {}
    # 解析ftp头部
    ftp_header['Request Type'] = app_packet[0: 8]
    ftp_header['Username'] = app_packet[8: 12]
    ftp_header['Password'] = app_packet[12: 16]
    ftp_header['Data Port'] = app_packet[16: 20]
    ftp_header['Server Response Code'] = app_packet[20: 24]
    ftp_header['Server Response Message'] = app_packet[24:]
    return ftp_header


def parse_smtp(app_packet):
    smtp_header = {}
    # 解析smtp头部
    smtp_header['Server Response Code'] = app_packet[0: 8]
    smtp_header['Server Response Message'] = app_packet[8:]
    return smtp_header

def parse_dns(app_packet):
    dns_header = {}
    # 解析dns头部
    dns_header['Transaction ID'] = app_packet[0: 2]
    dns_header['Flags'] = app_packet[2: 4]
    dns_header['Question Count'] = app_packet[4: 6]
    dns_header['Answer RRs'] = app_packet[6: 8]
    dns_header['Authority RRs'] = app_packet[8: 10]
    return dns_header

def parse_ssh(app_packet):
    ssh_header = {}
    # 解析ssh头部
    ssh_header['Protocol Version'] = app_packet[0: 2]
    ssh_header['Software Version'] = app_packet[2: 4]
    ssh_header['Connection Count'] = app_packet[4: 6]
    ssh_header['Cipher Specs Length'] = app_packet[6: 8]
    ssh_header['MAC Length'] = app_packet[8: 10]
    return ssh_header