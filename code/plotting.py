# Author: Pieter Robyns, 2017
# License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
# See LICENSE in this Git repository for the full license description

import numpy as np
import numpy.random
import matplotlib.pyplot as plt
import os
from scapy_tags import *

TAG_CAPA_ORDER = 253  # Custom element
TAG_MAC_FRAME = 254
TAG_ENTIRE_FRAME = 255

def make_stats(labels, matrix, name, output="latex/elt_entropy_table"):
    output += "_" + name
    with open(output, 'w') as outputfile:
        for i in range(0, len(labels)):
            outputfile.write("%s & %.3f\\\\\n" % (labels[i], sum(matrix[i])))

def make_heatmap(dictionary, range_x=None, inverted=True, show=True, name='heatmap.png'):
    if not os.path.exists("./latex"):
        os.makedirs("./latex")
    # Histogram example code
    #x = np.random.randn(8873)
    #y = np.random.randn(8873)
    #heatmap, xedges, yedges = np.histogram2d(x, y, bins=(50, 50))
    #extent = [xedges[0], xedges[-1], yedges[0], yedges[-1]]
    #fig = plt.imshow(data, origin='lower', extent=extent, cmap=plt.get_cmap('plasma'), interpolation='none')  # Other nice ones: inferno, Blues, YlOrBr
    if inverted:
        colormap = 'plasma_r'
    else:
        colormap = 'plasma'

    # Extract kv pairs while keeping order
    labels = []
    matrix = []
    for key in sorted(dictionary.keys()):
        if key == TAG_ENTIRE_FRAME:
            labels.append("Entire frame")
        elif key == TAG_MAC_FRAME:
            labels.append("MAC header")
        elif key == TAG_CAPA_ORDER:
            labels.append("Information element order")
        else:
            labels.append(human_readable_elt(key))
        matrix.append(dictionary[key])

    # Make a LaTeX table of the heatmap as well
    make_stats(labels, matrix, name)

    # Set data range
    plt.clf()
    if range_x is not None:
        matrix = [matrix[i][range_x[0]:range_x[1]] for i in range(0, len(matrix))]

    # Tick stuff
    plt.rcParams['ytick.labelsize'] = 8
    plt.gca().set_xticks(np.arange(0, len(matrix[0]), 8))
    plt.gca().set_yticks([i for i in range(0, len(labels))])
    plt.gca().set_yticklabels(labels)
    for t in plt.gca().xaxis.get_ticklines():
        t.set_color('white')
    for t in plt.gca().yaxis.get_ticklines():
        t.set_color('white')

    # Figure stuff
    plt.gcf().set_size_inches(20, 2.00)

    # Plot figure
    fig = plt.imshow(matrix, origin='lower', cmap=plt.get_cmap(colormap), interpolation='none', aspect='auto')  # Other nice ones: inferno, Blues, YlOrBr
    plt.colorbar(fig, orientation='vertical', pad=0.01)
    fig.set_clim(0.0, 1.0)
    plt.savefig(name, bbox_inches='tight', dpi=(300), format='pdf')
    if show:
        plt.show()


if __name__ == "__main__":
    data = np.clip(np.random.randn(15, 250), 0.5, 1)
    labels = ["a", "b", "c", "d"]
    make_heatmap(data, labels)
