from pyclustering.cluster import cluster_visualizer
from pyclustering.cluster.xmeans import xmeans
from pyclustering.cluster.center_initializer import kmeans_plusplus_initializer
from sklearn.preprocessing import normalize

class XmeansAlgorithm(object):
    def __init__(self, NxObj, amount_initial_centers=2, amount_max_centers=16):
        self.dataset = dict(NxObj.nodes.data())
        self.namelist = []
        self.datalist = []
        self.resultDict = {}
        self.amount_initial_centers = amount_initial_centers
        self.amount_max_centers = amount_max_centers

    def importData(self):
        for dp in self.dataset:
            self.namelist.append(dp)
            self.datalist.append([self.dataset[dp]['data']['SYNRequest'],
                                  self.dataset[dp]['data']['SYNAccept'] ,
                                  self.dataset[dp]['data']['flow']])
        self.datalist = normalize(self.datalist) # Normalize Data
        #del self.dataset

    def xmeansRoutine(self):

        self.initial_centers = kmeans_plusplus_initializer(self.datalist, self.amount_initial_centers).initialize()
        self.xmeans_instance = xmeans(self.datalist, self.initial_centers, self.amount_max_centers)
        self.xmeans_instance.process()
        self.clusters = self.xmeans_instance.get_clusters()
        self.centers = self.xmeans_instance.get_centers()

    def exportData(self):
        for clu, arr in enumerate(self.clusters):
            for n in arr:
                self.resultDict[self.namelist[n]] = clu

    def process(self):
        self.importData()
        self.xmeansRoutine()
        self.exportData()

    def getResult(self):
        return self.resultDict

    def getCenters(self):
        return self.centers

    def getVisualization(self):
        self.visualizer = cluster_visualizer()
        self.visualizer.append_clusters(self.clusters, self.datalist)
        self.visualizer.append_cluster(self.centers, None, marker='*', markersize=10)
        self.visualizer.show()
