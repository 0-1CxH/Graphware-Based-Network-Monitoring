import ipaddress

class ipv4address(object):
    def __init__(self,s): # s = string of IP address
        try:
            self.addr = ipaddress.IPv4Address(s)
        except:
            self.addr = None

    def isValid(self):
        if self.addr == None:
            return False
        else :
            return True

    def getStringIP(self):
        if self.isValid():
            return str(self.addr)
        else:
            return None

    def __str__(self):
        return self.getStringIP()

    def getDecimalIP(self):
        if self.isValid():
            return int(self.addr)
        else:
            return None

class ipv4range(object):
    def __init__(self,ls): # ls = list of STRING containing both ipaddress and ipnetwork
        self.rangeList = { 'host':[], 'network':[]} # host: contains strings, network: contains network objects
        self._cache = [] # cache the usually used ip with high possibility of repeating, format=STRING
        for s in ls:
            saddr = ipv4address(s)
            if saddr.isValid():
                self.rangeList['host'].append(saddr.getStringIP())
            try:
                snetwk = ipaddress.IPv4Network(s)
                self.rangeList['network'].append(snetwk)
            except:
                continue

    def has(self,s): # s = string of IP address
        try:
            s = ipv4address(s)
        except:
            return False
        if s.getStringIP() in self._cache: # mess a lot with the type converting
            return True
        else:
            if s.getStringIP() in self.rangeList['host']:
                self._cache.append(s.getStringIP())
                return True
            for ns in self.rangeList['network']:
                for nsh in ns.hosts(): # ATTENTION: objects with different location are not equal unless __eq__ defined
                    if s.getStringIP() == str(nsh):
                        self._cache.append(s.getStringIP())
                        return True
            return False


class port(object):
    def __init__(self,portnum): # portnum is integer or string
        if not isinstance(portnum, int):
            try:
                portnum = int(portnum)
            except:
                raise TypeError("Invalid Type of Port")
        if portnum<0 or portnum>65535:
            raise ValueError("Invalid Value of Port")
        else:
            self.value = portnum

    def __int__(self):
        return self.value


class portrange(object):
    def __init__(self, lp): # list of ports/ranges in STRING format (comma-separated)
        self.rangeList = {'single':set(), 'range':set()}
        self._cache = []
        self._omittedBcException = [] # list of omitted parts due to exception
        for p in lp:
            try:
                pp = port(p)
                self.rangeList['single'].add(pp.value)
            except TypeError:
                try:
                    plb, pub = p.split('-')
                except ValueError:
                    self._omittedBcException.append(p)
                    continue
                try:
                    pplb,ppub = port(plb), port(pub)
                    self.rangeList['range'].add(range(min(pplb.value,ppub.value),1+max(pplb.value,ppub.value)))
                except:
                    self._omittedBcException.append(p)
                    continue
            except ValueError:
                self._omittedBcException.append(p)
                continue
    def has(self,p):
        try:
            p = port(p)
        except:
            return False
        if p.value in self._cache:
            return True
        if p.value in self.rangeList['single']:
            self._cache.append(p.value)
            return True
        for pri in self.rangeList['range']:
            if p.value in pri:
                self._cache.append(p.value)
                return True
        return False


class numberRangeFilter(object):
    def __init__(self,ls): # list of strings
        self.rangeList = []
        self._allowall = False
        if len(ls) == 0:
            self._allowall = True
        for s in ls:
            if '-' not in s:
                continue
            else:
                try:
                    self.slb, self.sub = s.split('-')
                    self.slb, self.sub = int(self.slb), int(self.sub)
                    self.rangeList.append(range( min(self.slb,self.sub) , max(self.slb,self.sub)))
                except:
                    continue
    def has(self,number):
        if self._allowall:
            return True
        for r in self.rangeList:
            if number in r:
                return True
        return False


class dpktOctet(object): # Octet, not quintuple.
    # (TimeStamp, IPSrc, IPDst, PortSrc, PortDst, Protocol, Length) + (xInfo)
    def __init__(self, timestamp, ip_datagram):
        self.timestamp = timestamp
        self.sip = ipv4address(ip_datagram.src)  # sip and dip is saved in OBJECT format
        self.dip = ipv4address(ip_datagram.dst)
        self.proto = ip_datagram.p
        self._protoName = ip_datagram.get_proto(ip_datagram.p).__name__
        self.length = ip_datagram.len

        self.sport = 0
        self.dport = 0
        if hasattr(ip_datagram.data, 'sport'):
            self.sport = ip_datagram.data.sport
        if hasattr(ip_datagram.data, 'dport'):
            self.dport = ip_datagram.data.dport

        if self.proto == 1: # (Type,Code)
            self.xInfo = (ip_datagram.data.type, ip_datagram.data.code)
        elif self.proto == 6: # (ACK,RST,SYN,FIN)
            self.xInfo = ((ip_datagram.data.flags >> 4) & 1, (ip_datagram.data.flags >> 2) & 1,
                          (ip_datagram.data.flags >> 1) & 1, (ip_datagram.data.flags >> 0) & 1)
        else:
            self.xInfo = None

class protocolFilter(object):
    def __init__(self, lprtls):
        if len(lprtls) == 0:
            self._allowAll = True
        else:
            self._allowAll = False
            self.lprtls = lprtls

    def isallowed(self, protoName):
        return self._allowAll or (protoName in self.lprtls)

class dpktFilter(object):

    def __init__(self, filterconfig):
        lips, lps, lts, lls, lprtls = filterconfig
        # ARGS: list of ip string, list of port string, list of time string, list of length string, list of protocol string
        self.allIP = False
        self.allPort = False
        if len(lips) == 0 :
            self.allIP = True
        if len(lps) == 0:
            self.allPort = True
        self.ipFilter = ipv4range(lips)
        self.portFilter = portrange(lps)
        self.timeFilter = numberRangeFilter(lts)
        self.lengthFilter = numberRangeFilter(lls)
        self.protoFilter = protocolFilter(lprtls)

    def isSelected(self, dpktoct): # dpktOctet # test sequence: proto (O(1)) > number range (O(n)) > port (O(mn)) > IP (O(n^2))
        if not self.protoFilter.isallowed(dpktoct._protoName):
            return False
        if not self.timeFilter.has(dpktoct.timestamp):
            return False
        if not self.lengthFilter.has(dpktoct.length):
            return False
        if not self.allPort:
            if not self.portFilter.has(dpktoct.sport):
                return False
            if not self.portFilter.has(dpktoct.dport):
                return False
        if not self.allIP:
            if not self.ipFilter.has(dpktoct.sip.getStringIP()):
                return False
            if not self.ipFilter.has(dpktoct.dip.getStringIP()):
                return False
        return True

class quintupleConnection(object):
    def __init__(self, pac):
        self.ip = set(str(pac.sip), str(pac.dip))
        self.port = set(int(pac.sport), int(pac.dport))
        self.prtl = pac.proto
        self.status = None

    def __eq__(self, other):
        if self.ip == other.ip and self.port == other.port and self.prtl == other.prtl:
            return True





def test():
    s1 = ipv4range(["192.168.0.1","192.168.0.0/24","200.0.0.0/24"])
    s2 = portrange(["80", "8090-8082"])
    print(s1.rangeList)
    print(s1.has("192.168.0.100"))
    print(s1._cache)
    print(s1.has("192.168.0.100"))
    print(s2.rangeList)
    print(s2.has(8085))
    print(s2.has(8090))
    print(s2._cache)







