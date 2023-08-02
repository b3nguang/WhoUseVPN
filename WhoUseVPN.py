from time import sleep
import os
import tempfile
import dpkt
import requests
import socket

def extract_ips_from_pcap(pcap_file):
    ip_addresses = set()

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    src_ip = dpkt.utils.inet_to_str(ip.src)
                    dst_ip = dpkt.utils.inet_to_str(ip.dst)
                    ip_addresses.add(src_ip)
                    ip_addresses.add(dst_ip)
            except dpkt.dpkt.NeedData:
                continue
            except dpkt.dpkt.UnpackError:
                continue

    return list(ip_addresses)


# 调用函数，并传入pcap文件路径
pcap_file_path = r""
ips = extract_ips_from_pcap(pcap_file_path)


# print(ips)

def get_ip_location(ip_address):
    api_url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data
            else:
                return None
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        print(f"Error: {e}")
        return None


notCN = []

for ip in ips:
    flag = get_ip_location(ip)
    if flag:
        # country=flag['countryCode']
        country, region = flag['countryCode'], flag['region']
        print(country, region)
        if country != "CN" or region in ["TW", "HK"]:
            notCN.append(ip)

    # sleep(0.1)


def find_matching_ips(pcap_file, ip_list_file):
    pcap_ips = extract_ips_from_pcap(pcap_file)

    # 将target_ips从list转换为set
    with open(ip_list_file, 'r') as f:
        target_ips = set(line.strip() for line in f)

    # 将pcap_ips从list转换为set
    pcap_ips = set(pcap_ips)

    matching_ips = pcap_ips.intersection(target_ips)

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    if src_ip in matching_ips or dst_ip in matching_ips:
                        print(f"Packet with matching IP: Source IP: {src_ip}, Destination IP: {dst_ip}")
            except dpkt.dpkt.NeedData:
                continue
            except dpkt.dpkt.UnpackError:
                continue

# 将notCN列表中的IP地址写入一个临时文件
with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
    for ip in notCN:
        temp_file.write(ip + '\n')
    temp_file_path = temp_file.name

# 调用函数，并传入pcap文件路径和临时文件路径
find_matching_ips(pcap_file_path, temp_file_path)

# 删除临时文件
os.remove(temp_file_path)