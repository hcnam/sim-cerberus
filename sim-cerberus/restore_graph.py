#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import json
import math
import numpy as np

def draw_statistics_alone(j_datas: list, key: str, settings: list[str], filenames: list[str]):
    max_y = float('-inf')
    min_y = float('inf')
    for i in range(len(j_datas)):
        data = j_datas[i][key]
        for j in data:
            if j.lstrip('-').isdigit():
                max_y = max(max_y, max(data[j][1]))
                min_y = min(min_y, min(data[j][1]))

    for i in range(len(j_datas)):
        fig, ax = plt.subplots()

        data = j_datas[i][key]
        xlabel = data['xlabel']
        ylabel = data['ylabel']
        legend = data['legend']
        for j in data:
            if j.lstrip('-').isdigit():
                if len(data[j]) == 3:
                    ax.plot(data[j][0], data[j][1], color=data[j][2])
                elif len(data[j]) == 4:
                    ax.plot(data[j][0], data[j][1], label=data[j][2], color=data[j][3])

        if 'max_y' in data:
            max_y = data['max_y']
        if 'min_y' in data:
            min_y = data['min_y']
        margin = (max_y - min_y) * 0.05
        ymin, ymax = min_y-margin, max_y+margin
        if ymin == ymax:
            ymin -= (0.05 + 0.1*0.05)
            ymax += (0.05 + 0.1*0.05)
        ax.set_ylim([ymin, ymax])
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        if legend:
            ax.legend()

        fig.tight_layout()
        # fig.suptitle(settings[i], y=1.02, fontsize='x-large')
        fig.savefig(f"{filenames[i]}.png", bbox_inches='tight')

def draw_statistics(j_datas: list, j_key: list[str], settings: list[str], filenames: list[str]):
    if not j_key:
        return
    if len(j_key) == 1:
        draw_statistics_alone(j_datas, j_key[0], settings, filenames)
        return
    
    max_y = {key: float('-inf') for key in j_key}
    min_y = {key: float('inf') for key in j_key}
    for i in range(len(j_datas)):
        for key in j_key:
            data = j_datas[i][key]
            for j in data:
                if j.lstrip('-').isdigit():
                    num_data = list(filter(lambda x: x != None, data[j][1]))
                    max_y[key] = max(max_y[key], max(num_data))
                    min_y[key] = min(min_y[key], min(num_data))

    for i in range(len(j_datas)):
        ncols = 3 if len(j_key) >= 3 else len(j_key)
        nrows = math.ceil(len(j_key)/3)
        if ncols == 2:
            figsize = (12, 6)
        else:
            figsize = (4*ncols, 4*nrows)
        fig, axes = plt.subplots(ncols=ncols, nrows=nrows, figsize=figsize)
        axs = axes.ravel()
        axs_index = 0

        for key in j_key:
            data = j_datas[i][key]
            xlabel = data['xlabel']
            ylabel = data['ylabel']
            legend = data['legend']
            for j in data:
                if j.lstrip('-').isdigit():
                    if len(data[j]) == 3:
                        axs[axs_index].plot(data[j][0], data[j][1], color=data[j][2])
                    elif len(data[j]) == 4:
                        axs[axs_index].plot(data[j][0], data[j][1], label=data[j][2], color=data[j][3])

            if 'max_y' in data:
                max_y[key] = data['max_y']
            if 'min_y' in data:
                min_y[key] = data['min_y']
            margin = (max_y[key] - min_y[key]) * 0.05
            ymin, ymax = min_y[key]-margin, max_y[key]+margin
            if ymin == ymax:
                ymin -= (0.05 + 0.1*0.05)
                ymax += (0.05 + 0.1*0.05)
            axs[axs_index].set_ylim([ymin, ymax])
            axs[axs_index].set_xlabel(xlabel)
            axs[axs_index].set_ylabel(ylabel)
            if legend:
                axs[axs_index].legend()
            axs_index += 1

        fig.tight_layout()
        # fig.suptitle(settings[i], y=1.02, fontsize='xx-large')
        fig.savefig(f"{filenames[i]}.png", bbox_inches='tight')

def draw_statistics_poster(j_datas: list, j_key: list[str], settings: list[str], filenames: list[str]):
    # matplotlib.rcParams.update({'font.size': 15})

    if not j_key:
        return
    if len(j_key) == 1:
        draw_statistics_alone(j_datas, j_key[0], settings, filenames)
        return
    
    max_y = {key: float('-inf') for key in j_key}
    min_y = {key: float('inf') for key in j_key}
    for i in range(len(j_datas)):
        for key in j_key:
            data = j_datas[i][key]
            for j in data:
                if j.lstrip('-').isdigit():
                    num_data = list(filter(lambda x: x != None, data[j][1]))
                    max_y[key] = max(max_y[key], max(num_data))
                    min_y[key] = min(min_y[key], min(num_data))

    for i in range(len(j_datas)):
        ncols = 1
        nrows = math.ceil(len(j_key))
        figsize = (14*ncols, 4*nrows)
        fig, axes = plt.subplots(ncols=ncols, nrows=nrows, figsize=figsize)
        axs = axes.ravel()
        axs_index = 0

        for key in j_key:
            data = j_datas[i][key]
            xlabel = data['xlabel']
            ylabel = data['ylabel']
            legend = data['legend']
            for j in data:
                if j.lstrip('-').isdigit():
                    if len(data[j]) == 3:
                        axs[axs_index].plot(data[j][0], data[j][1], color=data[j][2], linewidth=3)
                    elif len(data[j]) == 4:
                        axs[axs_index].plot(data[j][0], data[j][1], label=data[j][2], color=data[j][3], linewidth=3)

            if 'max_y' in data:
                max_y[key] = data['max_y']
            if 'min_y' in data:
                min_y[key] = data['min_y']
            margin = (max_y[key] - min_y[key]) * 0.05
            ymin, ymax = min_y[key]-margin, max_y[key]+margin
            if ymin == ymax:
                ymin -= (0.05 + 0.1*0.05)
                ymax += (0.05 + 0.1*0.05)
            axs[axs_index].set_ylim([ymin, ymax])
            axs[axs_index].set_xlabel(xlabel)
            axs[axs_index].set_ylabel(ylabel)
            if legend:
                axs[axs_index].legend()
            axs_index += 1

        fig.tight_layout()
        # fig.suptitle(settings[i], y=1.02, fontsize='xx-large')
        fig.savefig(f"{filenames[i]}.png", bbox_inches='tight')

def draw_cp_max_bits(j_datas: list, settings: list[str], filenames: list[str]):
    max_y = float('-inf')
    for i in range(len(j_datas)):
        maxbits_used = j_datas[i]["maxbits_used"]["0"]
        for l in maxbits_used:
            max_y = max(max_y, l[2] + l[3])

    for i in range(len(j_datas)):
        maxbits_used = j_datas[i]["maxbits_used"]
        df = pd.DataFrame(columns=['Task', 'Tick', 'CP bits', 'DP bits'], data=maxbits_used["0"])
        df.set_index(['Task', 'Tick'], inplace=True)
        df0 = df.reorder_levels(['Tick', 'Task']).sort_index()
        colors = plt.cm.Paired.colors
        df0 = df0.unstack(level=-1)
        fig, ax = plt.subplots()
        ax.set_xlabel(maxbits_used['xlabel'])
        ax.set_ylabel(maxbits_used['ylabel'])
        margin = max_y * 0.05
        ax.set_ylim([0, max_y+margin])
        (df0['CP bits'] + df0['DP bits']).plot(kind='bar', color=[colors[2*i] for i in range(maxbits_used["tasks"])], rot=0, ax=ax)
        df0['DP bits'].plot(kind='bar', color=[colors[2*i+1] for i in range(maxbits_used["tasks"])], rot=0, ax=ax)
        if maxbits_used['legend']:
            handles, _ = plt.gca().get_legend_handles_labels()
            n = len(handles) // 2
            order = [i//2 + (i%2)*n for i in range(2*n)]
            prop = {'size': 32/n} if n >= 4 else None
            ax.legend([handles[idx] for idx in order],[maxbits_used['legend_labels'][idx] for idx in order], loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=n, prop=prop)
        plt.tight_layout()
        # fig.suptitle(settings[i], y=1.02, fontsize='x-large')
        plt.savefig(f"{filenames[i]} max bits.png", bbox_inches='tight')

if __name__ == "__main__":
    json_filenames = ["1_5_11_13 best with same time window 2025-02-04 01;18;39.790350",
                      "1_5_11_13 best with different time window 2025-02-04 20;51;47.183704"
                     ]
    j_key = [
             "relative_error",          # 4
             "fpr_info",                # 3
             "fnr_info",                # 3
             "counter_size",            # 4
             "uploaded_packet",         # 4
             "uploaded_packet_ratio",   # 4
             "rate",                    # 4
             "cp_not_processed",        # 3
            #  "mem_usage_info"
             "bandwidth_utilization",   # 3
            #  "overflowed_packet_ratio", # 4
             ]

    j_datas = []
    settings = []
    filenames = []
    for json_filename in json_filenames:
        with open(f"results/{json_filename}.json", mode="r") as j_object:
            j_datas.append(json.load(j_object))
        settings.append(j_datas[-1]["setting"].replace("/", " "))
        filenames.append(f"results/recovered {settings[-1]} {str(datetime.now()).replace(':', ';')}")
    draw_statistics(j_datas, j_key, settings, filenames)
    draw_cp_max_bits(j_datas, settings, filenames)
