#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import statistics
import numpy as np
import matplotlib.pyplot as plt
from run_sim import defense_dict

def make_label(filename: str) -> str:
    exp_name = filename.split(" ")[0]
    return "\n".join([defense_dict[int(x)] for x in exp_name.split("_")]) + f"\n({exp_name})"

def calc_mean_from_cdf(bins_count, cdf):
    # Convert lists back to numpy arrays
    bins_count = np.array([0] + bins_count)
    cdf = np.array(cdf)

    # Compute the PDF from the CDF
    pdf = np.diff(cdf, prepend=0)

    # Calculate the bin centers
    bin_centers = (bins_count[:-1] + bins_count[1:]) / 2

    # Calculate the mean
    return np.sum(pdf * bin_centers)

def main(dir_name: str, n_top: int, mode: str):
    folder_path = f"results/{dir_name}"
    cdf_key = {"relative_error" : "Relative error"}                         # 4
    ratio_key = {"fpr_info" : "FPR (%)",                                    # 4
                 "fnr_info" : "FNR (%)",                                    # 4
                 "uploaded_packet" : "Uploaded packet (M pps)",             # 4
                 "uploaded_packet_ratio" : "Uploaded packet (%)",           # 4
                 "cp_not_processed" : "Packets not processed by CP (%)",    # 3
                 "bandwidth_utilization" : "Bandwidth utilization (%)",     # 3
                 "overflowed_packet_ratio" : "Overflowed packet (%)",       # 4
                }
    if mode == "mean":
        agg = statistics.mean
    elif mode == "max":
        agg = max
    else:
        raise ValueError(f"Invalid mode: {mode}")

    json_filename = []
    cdf_average = {key: [] for key in cdf_key}
    ratio_agg = {key: [] for key in ratio_key}

    for filename in os.listdir(folder_path):
        if filename.endswith(".json") and "params" not in filename:
            file_path = os.path.join(folder_path, filename)
            with open(file_path, 'r', encoding='utf-8') as file:
                j_data = json.load(file)
                for key in cdf_key:
                    data = j_data[key]
                    cdf_mean = []
                    for i in data:
                        if i.lstrip('-').isdigit():
                            if len(data[i]) >= 3:
                                cdf_mean.append(calc_mean_from_cdf(data[i][0], data[i][1]))
                    cdf_average[key].append(statistics.mean(cdf_mean))
                for key in ratio_key:
                    data = j_data[key]
                    for i in data:
                        if i.lstrip('-').isdigit():
                            if len(data[i]) == 3:
                                ratio_agg[key].append(agg(data[i][1]))
                            elif len(data[i]) >= 4 and data[i][2] == "Global":
                                ratio_agg[key].append(agg(data[i][1]))
                json_filename.append(filename)
                for key in cdf_key:
                    if len(cdf_average[key]) != len(json_filename):
                        raise ValueError(f"Wrong parsing at: {json_filename}")
                for key in ratio_key:
                    if len(ratio_agg[key]) != len(json_filename):
                        raise ValueError(f"Wrong parsing at: {json_filename}")

    statistics_folder_path = f"{folder_path} stats {mode}/"
    if not os.path.exists(statistics_folder_path):
        os.makedirs(statistics_folder_path)
    for key in cdf_key:
        max_indices = sorted(range(len(cdf_average[key])), key=lambda i: cdf_average[key][i], reverse=True)[:n_top]
        max_labels = [make_label(json_filename[index]) for index in max_indices]
        max_values = [cdf_average[key][index] for index in max_indices]
        plt.figure(figsize=(10, 6))
        plt.bar(max_labels, max_values)
        plt.ylabel(cdf_key[key])
        plt.tight_layout()
        plt.suptitle(f"{dir_name} ({mode})", y=1.02, fontsize='x-large')
        plt.savefig(f"{statistics_folder_path}{key}.png", bbox_inches='tight')
    for key in ratio_key:
        max_indices = sorted(range(len(ratio_agg[key])), key=lambda i: ratio_agg[key][i], reverse=True)[:n_top]
        max_labels = [make_label(json_filename[index]) for index in max_indices]
        max_values = [ratio_agg[key][index] for index in max_indices]
        plt.figure(figsize=(10, 6))
        plt.bar(max_labels, max_values)
        plt.ylabel(ratio_key[key])
        plt.tight_layout()
        plt.suptitle(f"{dir_name} ({mode})", y=1.02, fontsize='x-large')
        plt.savefig(f"{statistics_folder_path}{key}.png", bbox_inches='tight')


if __name__ == '__main__':
    dir_name = "combination 3 no elephant"
    main(dir_name, 10, "mean")
    main(dir_name, 10, "max")
