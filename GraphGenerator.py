import networkx
import json

from networkx.readwrite import json_graph
import matplotlib.pyplot as plt

# EFP is UNdirected, UNIgraph, wEFP is weighted version of EFP
class wEFPConverterIncr(object): # Increamenting version of wEFP converter
    def __init__(self):
        self.NxObj = networkx.Graph()

    def update(self, pac): # pac is dpktOctet
        self._host1 = str(pac.sip)
        self._host2 = str(pac.dip)
        if self._host1 not in self.NxObj.nodes:
            self.NxObj.add_node(self._host1)
        if self._host2 not in self.NxObj.nodes:
            self.NxObj.add_node(self._host2)
        if (self._host1,self._host2) not in self.NxObj.edges:
            self.NxObj.add_edge(self._host1,self._host2, data={
                'starttime':pac.timestamp,
                'endtime':pac.timestamp,
                'duration':0,
                'count': 1,
                'flow': pac.length})
        else:
            self.NxObj.edges[self._host1,self._host2]['data']['endtime'] = pac.timestamp
            self.NxObj.edges[self._host1, self._host2]['data']['duration'] = pac.timestamp - self.NxObj.edges[self._host1,self._host2]['data']['starttime']
            self.NxObj.edges[self._host1, self._host2]['data']['count'] += 1
            self.NxObj.edges[self._host1, self._host2]['data']['flow'] += pac.length

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

