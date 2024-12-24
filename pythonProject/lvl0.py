from scapy.all import rdpcap, conf
from scapy.all import Ether, IP
from typing import Dict, List


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.packets = rdpcap(pcap_path)

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        raise NotImplementedError

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        raise NotImplementedError

    def get_info_by_mac(self, mac: str):
        """returns a dict with all information about the device with
        given MAC address"""
        info = self.get_info()
        for dic in info:
            if dic["MAC"] == mac:
                return dic
        raise {}

    def get_info_by_ip(self, ip: str):
        """returns a dict with all information about the device with
        given IP address"""
        info = self.get_info()
        for dic in info:
            if dic["IP"] == ip:
                return dic
        return {}

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        info = list()
        for packet in self.packets:
            mac: str = packet[Ether].src if Ether in packet else "Unknown"
            ip: str = packet[IP].src if IP in packet else "Unknown"
            vendor: str = conf.manufdb.lookup(mac)[0] if mac != "Unknown" else "Unknown"
            ttl: int = packet[IP].ttl if IP in packet else "Unknown"
            info.append({"MAC": mac, "IP": ip, "VENDOR": vendor, "TTL": ttl})
        return [e for i, e in enumerate(info) if e not in info[:i]]

    @staticmethod
    def guess_os(device_info: Dict[str, Dict]) -> List[str]:
        """returns assumed operating system of a device"""
        if "TTL" not in device_info:
            return []
        ttl = device_info["TTL"]
        guess = set()
        if ttl == 128:
            guess.add("Windows")
        elif ttl == 64:
            guess.add("Linux")
            guess.add("macOS")
        elif ttl == 255:
            guess.add("Network Device")
        return list(guess)

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


if __name__ == "__main__":
    path: str = "C:\\Users\\User\\Desktop\\Mooli\\Arazim\\PP7070\\Networks\\guess-who\\pcap-01.pcapng"
    an = AnalyzeNetwork(path)
    information = an.get_info()
    print(information)
    print(an.guess_os(an.get_info_by_mac("00:0c:29:1d:1e:8f")))
    print(an.guess_os(an.get_info_by_ip("172.17.174.113")))
