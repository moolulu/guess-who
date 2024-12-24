from scapy.all import rdpcap, conf
from scapy.all import Ether, IP, ICMP
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
            device_info = dict()
            device_info["MAC"] = packet[Ether].src if Ether in packet else "Unknown"
            device_info["IP"] = packet[IP].src if IP in packet else "Unknown"
            device_info["VENDOR"] = conf.manufdb.lookup(device_info["MAC"])[0] if device_info["MAC"] != "Unknown" else "Unknown"
            if IP in packet:
                device_info["TTL"] = packet[IP].ttl
                device_info["FLAGS"] = packet[IP].flags
            if ICMP in packet:
                device_info["PAYLOAD SIZE"] = len(packet[ICMP].payload)
            info.append(device_info)

        return [e for i, e in enumerate(info) if e not in info[:i]]

    @staticmethod
    def guess_os(device_info: Dict[str, Dict]) -> List[str]:
        """returns assumed operating system of a device"""
        guess = set()

        if "TTL" in device_info:
            ttl = device_info["TTL"]
            if ttl == 128:
                guess.add("Windows")
            elif ttl == 64:
                guess.add("Linux")
                guess.add("macOS")
            elif ttl == 255:
                guess.add("Network Device")

        if "FLAGS" in device_info:
            flags = device_info["FLAGS"]
            dont_fragment = flags & 0x2 != 0
            if dont_fragment:
                guess.add("Windows")

        if "PAYLOAD SIZE" in device_info:
            payload_size = device_info["PAYLOAD SIZE"]
            if payload_size == 56:
                guess.add("Linux")
            if payload_size == 32:
                guess.add("Windows")

        return list(guess)

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


if __name__ == "__main__":
    path: str = "C:\\Users\\User\\Desktop\\Mooli\\Arazim\\PP7070\\Networks\\guess-who\\pcap-02.pcapng"
    an = AnalyzeNetwork(path)
    information = an.get_info()
    print(information)
    print(an.guess_os(an.get_info_by_mac("00:0c:29:1d:1e:8f")))
    print(an.guess_os(an.get_info_by_ip("192.168.226.1")))
