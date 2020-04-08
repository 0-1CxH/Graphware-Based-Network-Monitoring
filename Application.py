import numpy as np
import matplotlib.pyplot as plt
import json
from Algorithm import XmeansAlgorithm

class modifiedEdgeCentricAnalyzer(object):
    def __init__(self, NxObj):
        self.NxObj = NxObj
        self.globalStat = {}
        self.distribution = {}
        self.anormlyscoredict = {}
        # structure: {
        # [clusternumber]:{
        #   attachednodes: {
        #      [nodename]:
        #       {   [attrname]:{distribution}  }
        #    }
        #   clusterstat:{[attrname]:{distribution}}
        #   }
        # }

    def calculatenodestat(self):
        self._durarray, self._countarray, self._flowarray = np.split(self._dataarray, 3, axis=1)
        self._durarray[self._durarray == 0] = -1 # make 0 duration negative to identify
        # calculate each indicator
        self._avesizearr = self._flowarray / self._countarray
        self._avesizearr[self._avesizearr < 0] = 10 ** -6
        self._avedataratearr = self._flowarray / self._durarray
        self._avedataratearr[self._avedataratearr < 0] = 10 ** -6 # make negative time a small value and bin to 0
        self._avefreqarr = self._countarray / self._durarray
        self._avefreqarr[self._avefreqarr < 0] = 10 ** -6  # make negative time a small value and bin to 0
        # log2 binning + counting
        # Can use np.digitize(arr, np.logspace(arr.min,arr.max,d)) instead but this min/max is not global
        def onehotencode(arr): # use one hot encoding to represent the vectors
            arr = np.floor(np.log2(arr)/np.log2(1.2)).reshape(1,-1) # TODO: change the binning function
            arr[ arr < 1] = 0
            arr = arr.astype(np.int)
            arrstat = np.zeros((arr.size, arr.max() + 1))
            arrstat[np.arange(arr.size),arr] = 1
            arrstat = arrstat.sum(axis=0)
            return arrstat
        return onehotencode(self._avesizearr), onehotencode(self._avedataratearr), onehotencode(self._avefreqarr)


    def calculateclusterstat(self):
        def addVecs(v1,v2):
            s_diff =  np.size(v1) - np.size(v2)
            if s_diff > 0:
                v2 = np.append(v2, [0]*s_diff)
            else :
                v1 = np.append(v1, [0]*(-s_diff))
            return v1+v2
        self.globalStat['globalsizestat'] = np.array([])
        self.globalStat['globalratestat'] = np.array([])
        self.globalStat['globalfreqstat'] = np.array([])
        for clu in self.distribution:
            cur_clu = self.distribution[clu]
            cur_clu['clusterstat'] = {}
            self._clusizestat = np.array([])
            self._cluratestat = np.array([])
            self._clufreqstat = np.array([])
            for atnd in cur_clu['attachednodes']: # update cluster stat by nodes
                cur_atnd = cur_clu['attachednodes'][atnd]
                self._clusizestat = addVecs(cur_atnd['sizestat'], self._clusizestat)
                self._cluratestat = addVecs(cur_atnd['ratestat'], self._cluratestat)
                self._clufreqstat = addVecs(cur_atnd['freqstat'], self._clufreqstat)
            # export cluster stat
            cur_clu['clusterstat']['clustersizestat'] = self._clusizestat
            cur_clu['clusterstat']['clusterratestat'] = self._cluratestat
            cur_clu['clusterstat']['clusterfreqstat'] = self._clufreqstat
            # update global stat (FOR Jelinek-Mercer Smoothing)
            self.globalStat['globalsizestat'] = addVecs(self.globalStat['globalsizestat'], self._clusizestat)
            self.globalStat['globalratestat'] = addVecs(self.globalStat['globalratestat'], self._cluratestat)
            self.globalStat['globalfreqstat'] = addVecs(self.globalStat['globalfreqstat'], self._clufreqstat)

    def anomalyscore(self):
        def addVecs(v1,v2):
            s_diff =  np.size(v1) - np.size(v2)
            if s_diff > 0:
                v2 = np.append(v2, [0]*s_diff)
            else :
                v1 = np.append(v1, [0]*(-s_diff))
            return v1+v2
        def kldivergence(v1, v2, vg, miu=len(self.NxObj.nodes)): # vg and miu are J-K smoothing arguments
            v1 = v1/v1.sum()
            v2 = addVecs(v2, (1/miu)*vg)
            v2 = v2/v2.sum()
            s_diff =  np.size(v1) - np.size(v2)
            if s_diff > 0:
                v2 = np.append(v2, [0]*s_diff)
            else :
                v1 = np.append(v1, [0]*(-s_diff))
            return np.sum(np.where(v1 != 0, v1 * np.log(v1 / v2), 0)) # KL(P||Q)
        # Problem: v1!=0 but v2==0 ?
        # [Fix: Jelinek-Mercer Smoothing] use global stat to do J-K SMOOTHING

        for clu in self.distribution:
            cur_clu = self.distribution[clu]
            for atnd in cur_clu['attachednodes']:
                cur_atnd = cur_clu['attachednodes'][atnd]
                cur_atnd_kl = 0
                for compare_clu in self.distribution:
                    cur_atnd_cur_compare_clu_kl = 0
                    cur_compare_clu = self.distribution[compare_clu]
                    cur_compare_clu_proportion =  len(cur_compare_clu['attachednodes']) / len(self.NxObj.nodes)
                    cur_atnd_cur_compare_clu_kl += kldivergence(cur_atnd['sizestat'], cur_compare_clu['clusterstat']['clustersizestat'], self.globalStat['globalsizestat'] )
                    cur_atnd_cur_compare_clu_kl += kldivergence(cur_atnd['ratestat'], cur_compare_clu['clusterstat']['clusterratestat'], self.globalStat['globalratestat'])
                    cur_atnd_cur_compare_clu_kl += kldivergence(cur_atnd['freqstat'], cur_compare_clu['clusterstat']['clusterfreqstat'], self.globalStat['globalfreqstat'])
                    cur_atnd_cur_compare_clu_kl = cur_atnd_cur_compare_clu_kl * cur_compare_clu_proportion
                    cur_atnd_kl += cur_atnd_cur_compare_clu_kl
                cur_atnd['kldivergence'] = cur_atnd_kl

    def process(self):
        # create xmeans object
        self.xmalgoObj = XmeansAlgorithm(self.NxObj)
        self.xmalgoObj.process()
        self.xmalgoResult = self.xmalgoObj.getResult()
        self.xmalgoCenter = self.xmalgoObj.getCenters()
        # import xmeans result
        for nd in self.xmalgoResult:
            self.NxObj.nodes[nd]['data']['cluster'] = self.xmalgoResult[nd]
        # delete xmeans object
        del self.xmalgoObj
        #del xmalgoResult
        # get distributions
        for nd in self.NxObj.nodes: # each node
            cur_nd = self.NxObj.nodes[nd]
            if cur_nd['data']['cluster'] not in self.distribution:
                self.distribution[cur_nd['data']['cluster']] = { 'attachednodes':{}, 'clusterstat':{} }
            if nd not in self.distribution[cur_nd['data']['cluster']]['attachednodes']:
                self.distribution[cur_nd['data']['cluster']]['attachednodes'][nd] = {}
            self._dataarray = np.array([])
            for adjnd in self.NxObj.adj[nd]: # each adj edge of node
                cur_eg = self.NxObj.edges[nd,adjnd] # update data array with each edge
                if len(self._dataarray)==0 :
                    self._dataarray = np.array([cur_eg['data']['duration'], cur_eg['data']['count'], cur_eg['data']['flow']])
                else:
                    self._dataarray = np.append(self._dataarray, [cur_eg['data']['duration'], cur_eg['data']['count'], cur_eg['data']['flow']])
            self._dataarray = self._dataarray.reshape(-1,3) # prepare data array for node stat
            self._sizestat, self._ratestat, self._freqstat = self.calculatenodestat()
            # export result to distribution dict
            self.distribution[cur_nd['data']['cluster']]['attachednodes'][nd]['sizestat'] = self._sizestat
            self.distribution[cur_nd['data']['cluster']]['attachednodes'][nd]['ratestat'] = self._ratestat
            self.distribution[cur_nd['data']['cluster']]['attachednodes'][nd]['freqstat'] = self._freqstat
        self.calculateclusterstat()
        self.anomalyscore()

    def exportNetworkxObj(self):
        for clu in self.distribution:
            cur_clu = self.distribution[clu]
            for atnd in cur_clu['attachednodes']:
                self.NxObj.nodes[atnd] = {}
                self.NxObj.nodes[atnd]['data']['kldivergence'] = cur_clu['attachednodes'][atnd]['kldivergence']
                self.NxObj.nodes[atnd]['data']['clusternumber'] = clu
        return self.NxObj

    def exportAnomalyScore(self, outputfilename=None):
        if len(self.anormlyscoredict) == 0:
            for clu in self.distribution:
                cur_clu = self.distribution[clu]
                for atnd in cur_clu['attachednodes']:
                    self.anormlyscoredict[atnd] = {}
                    self.anormlyscoredict[atnd]['kldivergence'] = cur_clu['attachednodes'][atnd]['kldivergence']
                    self.anormlyscoredict[atnd]['clusternumber'] = clu
        if outputfilename:
            with open(outputfilename,"w") as f:
                f.write(json.dumps(self.anormlyscoredict))
        return self.anormlyscoredict

    def getDistributionDict(self):
        return self.distribution

    def getClusteringResults(self):
        return self.xmalgoResult, self.xmalgoCenter

    def getGlobalStat(self):
        return self.globalStat

    def visualize(self):
        '''
        ndnames = []
        klds= []
        clus = []
        for item in self.anormlyscoredict:
            ndnames.append(item)
            klds.append(self.anormlyscoredict[item]['kldivergence'])
            clus.append(self.anormlyscoredict[item]['clusternumber'])
        plt.scatter(klds, clus)
        plt.show()
        '''


    # TODO: visulization function

