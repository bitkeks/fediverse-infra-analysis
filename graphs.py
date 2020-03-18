"""
Mastodon infrastructure analysis tool. See README for usage.
Copyright 2020 Dominik Pataky <dev@bitkeks.eu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import matplotlib.pyplot as plt
import numpy as np

plt.set_cmap('Paired')
FONTSIZE = 9


def autolabel(ax, rects):
    max_h = max([r.get_height() for r in rects])
    for rect in rects:
        height = rect.get_height()
        is_near_top = (height / max_h) > 0.8
        va, xytext = ('top', (0, -3)) if is_near_top else ('bottom', (0, 3))
        rotation = 'horizontal' if height < 100 else 'vertical'
        ax.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=xytext,
                    textcoords="offset points",
                    horizontalalignment='center',
                    verticalalignment=va,
                    color='white' if is_near_top else 'black',
                    rotation=rotation,
                    fontsize=8,
                    zorder=1000)


def plot_by_instances(*args, **kwargs):
    _plot(True, *args, filename="graph_instances.png", sorted_by="instances", **kwargs)


def plot_by_users(*args, **kwargs):
    _plot(False, *args, filename="graph_users.png", sorted_by="users", **kwargs)


def plot_by_active_users(*args, **kwargs):
    _plot(False, *args, filename="graph_active_users.png", sorted_by="active users", **kwargs)


def _plot(sorted_by_instances: bool, x, y1, y2, filename: str, sorted_by: str):
    if not filename:
        raise ValueError

    fig, ax1 = plt.subplots(1, 1, figsize=(14, 6))

    x_ar = np.arange(len(x))
    num_instances = sum(y1) if sorted_by_instances else sum(y2)
    width = 0.4  # the width of the bars

    colors = {
        "users": "xkcd:leaf green",
        "instances": "xkcd:cornflower blue"
    }

    ax1.set_xlabel('Hosting provider (AS)')

    ylabel = "Number of instances hosted" if sorted_by_instances else "Number of users hosted"
    ax1.set_ylabel(ylabel, fontsize=FONTSIZE)

    rects1 = ax1.bar(x_ar - width / 2, y1, width,
                     color=colors["instances" if sorted_by_instances else "users"],
                     zorder=50)
    ax1.tick_params(axis='y')

    ax1.set_xticks(ticks=x_ar)
    ax1.set_xticklabels(x, {'fontsize': FONTSIZE, 'rotation': 15, 'horizontalalignment': 'right'})
    ax1.set_xmargin(0.01)  # margin factor left and right
    # ax1.grid(axis='y', zorder=10)

    # shifting of x-axis labels
    # for tick in ax1.xaxis.get_major_ticks()[1::2]:
    #     tick.set_pad(20)

    ax1.set_title('Mastodon infrastructure in 2020 - top {} instances (sorted by {}, '
                  'source instances.social {}, published @ bitkeks.eu)'.format(
                    num_instances, sorted_by, "2020-03-04"),
                  fontsize=10)

    ax2 = ax1.twinx()
    ylabel = "Number of users hosted" if sorted_by_instances else "Number of instances hosted"
    ax2.set_ylabel(ylabel, fontsize=FONTSIZE)
    rects2 = ax2.bar(x_ar + width / 2, y2, width,
                     color=colors["users" if sorted_by_instances else "instances"],
                     alpha=0.2, zorder=50)
    ax2.tick_params(axis='y')

    autolabel(ax1, rects1)
    autolabel(ax2, rects2)

    # legend
    labels = ["hosted instances", "hosted users"] if sorted_by_instances \
        else ["hosted {}".format(sorted_by), "hosted instances"]
    rects = [rects1, rects2]
    plt.legend(rects, labels, loc='upper center')

    fig.tight_layout()
    plt.savefig(filename, format='png', transparent=False)
