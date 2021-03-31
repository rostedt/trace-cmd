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
x = data[:, 0]
y = data[:, 1]

fig, ax = plt.subplots()

ax.set_xlabel('samples (t)')
ax.set_ylabel('clock offset')
ax.set_title("$\delta$=%i ns" % (max(y) - min(y)))

l = mlines.Line2D(x, y)
ax.add_line(l)
ax.set_xlim(min(x), max(x))
ax.set_ylim(min(y), max(y) )

print(min(y), max(y), max(y) - min(y))

# Tweak spacing to prevent clipping of ylabel
fig.tight_layout()
plt.show()
