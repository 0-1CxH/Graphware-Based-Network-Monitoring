import networkx
import json

from networkx.readwrite import json_graph
import matplotlib.pyplot as plt

from Common import quintupleConnection

# EFP is UNdirected, UNIgraph, wEFP is weighted version of EFP
class wEFPConverterIncr(object): # Increamenting version of wEFP converter
    def __init__(self, TCPSYNtrack=True):
        self.NxObj = networkx.Graph()
        self.TCPSYNtrack = TCPSYNtrack
        self.globalData = {'nodeCount':0, 'edgeCount':0, 'starttime':0, 'endtime':0}

    def update(self, pac): # pac is dpktOctet
        # UPDATE NODE
        self._host1 = str(pac.sip)
        self._host2 = str(pac.dip)
        if self._host1 not in self.NxObj.nodes:
            if self.TCPSYNtrack:
                self.NxObj.add_node(self._host1, data={'SYNRequest':0, 'SYNAccept':0, 'flow':0})
            else:
                self.NxObj.add_node(self._host1, data={'flow':0})
            self.globalData['nodeCount'] += 1
        if self._host2 not in self.NxObj.nodes:
            if self.TCPSYNtrack:
                self.NxObj.add_node(self._host2, data={'SYNRequest':0, 'SYNAccept':0, 'flow':0})
            else:
                self.NxObj.add_node(self._host2, data={'flow':0})
            self.globalData['nodeCount'] += 1
        self.NxObj.nodes[str(pac.sip)]['data']['flow'] += pac.length
        self.NxObj.nodes[str(pac.dip)]['data']['flow'] += pac.length
        # UPDATE EDGE
        if ((self._host1,self._host2) not in self.NxObj.edges) or ((self._host2,self._host1) not in self.NxObj.edges):
            self.NxObj.add_edge(self._host1,self._host2, data={
                'starttime':pac.timestamp,
                'endtime':pac.timestamp,
                'duration':0,
                'count': 1,
                'flow': pac.length})
            self.globalData['edgeCount'] += 1
        else:
            self.NxObj.edges[self._host1,self._host2]['data']['endtime'] = pac.timestamp
            self.NxObj.edges[self._host1, self._host2]['data']['duration'] = pac.timestamp - self.NxObj.edges[self._host1,self._host2]['data']['starttime']
            self.NxObj.edges[self._host1, self._host2]['data']['count'] += 1
            self.NxObj.edges[self._host1, self._host2]['data']['flow'] += pac.length
        # UPDATE GLOBAL
        if pac.timestamp > self.globalData['endtime']:
            self.globalData['endtime'] = pac.timestamp
        # SYN Track
        if self.TCPSYNtrack == True:
            if pac.proto == 6:
                if pac.xInfo[2]!=0 and pac.xInfo[0]==0 : #SYN
                    self.NxObj.nodes[str(pac.sip)]['data']['SYNRequest'] += 1
                    self.NxObj.nodes[str(pac.dip)]['data']['SYNAccept'] += 1
        #debug
        #print(self.globalData)

    def exportNetworkxObj(self):
        return self.NxObj

    def exportJSON(self, outputfilename=None):
        jsondata = json_graph.node_link_data(self.NxObj)
        if outputfilename:
            with open(outputfilename,"w") as f:
                f.write(json.dumps(jsondata))
        return jsondata

# TODO: conntrackConverter
class conntrackConverter(object):
    def __init__(self):
        self.NxObj = networkx.MultiDiGraph()

    def update(self, pac):
        pass

