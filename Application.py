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

    def process(self):
        # create xmeans object
        xmalgoObj = XmeansAlgorithm(a.graphConverter.exportNetworkxObj())
        xmalgoObj.process()
        xmalgoResult = xmalgoObj.getResult()
        # import xmeans result
        for nd in xmalgoResult:
            self.NxObj.nodes[nd]['data']['cluster'] = xmalgoResult[nd]
        # delete xmeans object
        del xmalgoObj
        del xmalgoResult
        # get distributions

        # get kl divergence
