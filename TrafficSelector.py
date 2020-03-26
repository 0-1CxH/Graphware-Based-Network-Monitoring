from Common import dpktOctet, dpktFilter
import dpkt

class dpktTrafficSelector(object):
    def __init__(self, trafficfilename, filterConfig=([],["1-4096","6000-20000"],[],[],["TCP","UDP"])):
        self.f = open(trafficfilename, 'rb')
        self.pcapIter = dpkt.pcap.Reader(self.f)
        self.selectedPackets = []
        self._totalCount = 0
        self._ipCount = 0
        self._filteredCount = 0
        self.initTimestamp = -1
        for timestamp, buf in self.pcapIter:
            if self.initTimestamp == -1:
                self.initTimestamp = timestamp
            self._totalCount += 1
            eth = dpkt.ethernet.Ethernet(buf)  # Unpack the Ethernet frame (mac src/dst, ethertype)
            # Make sure the Ethernet frame contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            self.c_packet = dpktOctet(timestamp-self.initTimestamp, ip)
            self._ipCount += 1
            self.filterObj = dpktFilter(filterConfig)
            if self.filterObj.isSelected(self.c_packet):
                self.selectedPackets.append(self.c_packet)
                self._filteredCount += 1
        self.f.close()

    def getCount(self):
        return (self._totalCount, self._ipCount, self._filteredCount)


# a = dpktTrafficSelector("MAWI100K.pcap")
# print(a.getCount())
