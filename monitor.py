import json
import sys
import matplotlib.pyplot as plt
import matplotlib.animation as anim


def loadStats(archivename):
    with open(archivename) as fp:
        return(json.load(fp))

def plotGraph(stats):
    x = stats["3"]["timestamps"]
    y = stats["3"]["path"]
    columns = ('s1', 's2', 's3', 's4', 's5', 's6')
    plt.figure(1)
    plt.plot(x, y, linestyle='--', c='#FF0000')
    plt.title("Simple Plot")
    plt.show()


if __name__ == "__main__":
    archivename = "data/" + sys.argv[1]
    stats = loadStats(archivename)
    plotGraph(stats)
