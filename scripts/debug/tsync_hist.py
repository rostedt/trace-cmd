# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2019, VMware Inc, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
# Copyright (C) 2019, VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>


import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import sys

def newline(p1, p2):
    ax = plt.gca()
    xmin, xmax = ax.get_xbound()

    if(p2[0] == p1[0]):
        xmin = xmax = p1[0]
        ymin, ymax = ax.get_ybound()
    else:
        ymax = p1[1]+(p2[1]-p1[1])/(p2[0]-p1[0])*(xmax-p1[0])
        ymin = p1[1]+(p2[1]-p1[1])/(p2[0]-p1[0])*(xmin-p1[0])

    l = mlines.Line2D([xmin,xmax], [ymin,ymax], color='red')
    ax.add_line(l)
    return l


data = np.loadtxt(fname = sys.argv[1])
selected_ts  = data[-1, 1]
selected_ofs = data[-1, 0]
data = data[:-1,:]

x = data[:, 1] - data[:, 0]

mean = x.mean()
std = x.std()

num_bins = 500
min = x.min() #+ .4 * (x.max() - x.min())
max = x.max() #- .4 * (x.max() - x.min())
bins = np.linspace(min, max, num_bins, endpoint = False, dtype=int)

fig, ax = plt.subplots()

# the histogram of the data
n, bins, patches = ax.hist(x, bins, histtype=u'step');

ax.set_xlabel('clock offset [$\mu$s]')
ax.set_ylabel('entries')
ax.set_title("$\sigma$=%i" % std)

x1, y1 = [selected_ofs, min], [selected_ofs, max]
newline(x1, y1)

# Tweak spacing to prevent clipping of ylabel
fig.tight_layout()
plt.show()
