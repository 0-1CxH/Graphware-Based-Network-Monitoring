import dpkt
from Common import dpktOctet, dpktFilter
from GraphGenerator import wEFPConverterIncr

class dpktTrafficSelector(object):
    def __init__(self, trafficfilename, filterConfig=([],[],[],[],[]), converterName="wEFP"):
        self.f = open(trafficfilename, 'rb')
        self.pcapIter = dpkt.pcap.Reader(self.f)
        self._totalCount = 0
        self._ipCount = 0
        self._filteredCount = 0
        self.initTimestamp = -1
        if converterName == "EFP" or "wEFP": # Now EFP and wEFP is combined, implemented as wEFPConverterIncr
            self.graphConverter = wEFPConverterIncr()
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
                #print(self.c_packet.timestamp,self.c_packet.proto,self.c_packet.length)
                self.graphConverter.update(self.c_packet) # No longer use Iteration, use Increment instead. Less memory space
                self._filteredCount += 1
        self.f.close()
        #self.graphConverter.drawdemo()
        self.graphConverter.exportJSON("1.json")

    def getCount(self):
        return {"Total":self._totalCount, "Valid IP":self._ipCount, "Selected":self._filteredCount}

# TODO: Implement pysharkTrafficSelector


a = dpktTrafficSelector(trafficfilename="MAWI100K.pcap", filterConfig=([],["1-4096","6000-20000"],[],[],["TCP","UDP"]))
print(a.getCount())
print(a.graphConverter.globalData)
def testXmeans():
    from Algorithm import XmeansAlgorithm
    b = XmeansAlgorithm(a.graphConverter.exportNetworkxObj())
    b.process()
    print(b.clusters)
    print(len(b.clusters))
    b.getVisualization()
testXmeans()