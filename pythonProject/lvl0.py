from scapy.all import rdpcap, conf
from scapy.all import Ether, IP


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

    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        raise NotImplementedError

    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        raise NotImplementedError

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        info = list()
        for packet in self.packets:
            mac: str = packet[Ether].src if Ether in packet else "Unknown"
            ip: str = packet[IP].src if IP in packet else "Unknown"
            vendor: str = conf.manufdb.lookup(mac) if mac != "Unknown" else "Unknown"
            info.append({"MAC": mac, "IP": ip, "VENDOR": vendor})
        return [e for i, e in enumerate(info) if e not in info[:i]]

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


if __name__ == "__main__":
    path: str = "C:\\Users\\User\\Desktop\\Mooli\\Arazim\\PP7070\\Networks\\guess-who\\pcap-00.pcapng"
    an = AnalyzeNetwork(path)
    print(an.get_info())
