import numpy as np
from Algorithm import XmeansAlgorithm

def testXmeans():
    b = XmeansAlgorithm(a.graphConverter.exportNetworkxObj())
    b.process()
    print(b.getResult())
    print(b.getCenters())
    print(b.clusters)
    print(len(b.clusters))
    b.getVisualization()
#testXmeans()

class modifiedEdgeCentricAnalyzer(object):
    def __init__(self, NxObj):
        self.NxObj = NxObj
        self.distribution = {}
        # structure: {
        # [clusternumber]:{
        #   attachednodes: {
        #      [nodename]:
        #       {   [attrname]:{distribution}  }
        #    }
        #   stat:{[attrname]:{distribution}}
        #   }
        # }

    def aggregate(self):
        self._durarray, self._countarray, self._flowarray = np.split(self._dataarray, 3, axis=1)
        self._durarray[self._durarray == 0] = -1
        self._avesizearr = self._countarray / self._durarray
        self._avesizearr[self._avesizearr < 0] = 10 ** -6
        self._avedataratearr = self._flowarray / self._durarray
        self._avedataratearr[self._avedataratearr < 0] = 10 ** -6
        # log2 binning + counting
        # Can use np.digitize and np.logspace to do binning
        def onehotencode(arr):
            arr = np.floor(np.log2(arr)).reshape(1,-1)
            arr[ arr < 1] = 0
            arr = arr.astype(np.int)
            arrstat = np.zeros((arr.size, arr.max() + 1))
            arrstat[np.arange(arr.size),arr] = 1
            arrstat = arrstat.sum(axis=0)
            return arrstat
        # debug
        return onehotencode(self._avesizearr), onehotencode(self._avedataratearr)

    def process(self):
        # create xmeans object
        xmalgoObj = XmeansAlgorithm(self.NxObj)
        xmalgoObj.process()
        xmalgoResult = xmalgoObj.getResult()
        # import xmeans result
        for nd in xmalgoResult:
            self.NxObj.nodes[nd]['data']['cluster'] = xmalgoResult[nd]
        # delete xmeans object
        del xmalgoObj
        del xmalgoResult
        # get distributions
        for nd in self.NxObj.nodes: # each node
            cur_nd = self.NxObj.nodes[nd]
            if cur_nd['data']['cluster'] not in self.distribution:
                self.distribution[cur_nd['data']['cluster']] = { 'attachednodes':{}, 'stat':{} }
            if nd not in self.distribution[cur_nd['data']['cluster']]['attachednodes']:
                self.distribution[cur_nd['data']['cluster']]['attachednodes'][nd] = {}
            self._dataarray = np.array([])
            for adjnd in self.NxObj.adj[nd]:
                cur_eg = self.NxObj.edges[nd,adjnd]
                if len(self._dataarray)==0 :
                    self._dataarray = np.array([cur_eg['data']['duration'], cur_eg['data']['count'], cur_eg['data']['flow']])
                else:
                    self._dataarray = np.append(self._dataarray, [cur_eg['data']['duration'], cur_eg['data']['count'], cur_eg['data']['flow']])
            self._dataarray = self._dataarray.reshape(-1,3)
            self._sizestat, self._ratestat = self.aggregate()
            self.distribution[cur_nd['data']['cluster']]['attachednodes'][nd]['sizestat'] = self._sizestat
            self.distribution[cur_nd['data']['cluster']]['attachednodes'][nd]['ratestat'] = self._ratestat
        print(self.distribution)





            #self.distribution[cur_nd['data']['cluster']]


        # get kl divergence
