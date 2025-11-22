#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from itertools import combinations
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
import time
import os
import glob
import flowkey

exclude_exp = [3, 14, 15]               # Coremelt, ACK flood, RST/FIN flood
large_exp = [12, 13, 14, 15]

def file_exists(directory: str, prefix: str) -> bool:
    pattern = os.path.join(directory, f"{prefix}*")
    matching_files = glob.glob(pattern)
    return True if matching_files else False

def run_program(param_filename: str, exp_name: str):
    with open(f"log/{param_filename}.out", 'w') as out_file, open(f"log/{param_filename}.err", 'w') as err_file:
        subprocess.run(
            ['python3', 'run_sim.py', param_filename, exp_name],
            stdout=out_file,
            stderr=err_file,
            text=True
        )

def exp_count(n_comb: int, exp_name: str):
    combination_path = f"combination {n_comb} {exp_name}/" if exp_name else f"combination {n_comb}/"
    if not os.path.exists(f"results/{combination_path}"):
        os.makedirs(f"results/{combination_path}")
    if not os.path.exists(f"log/{combination_path}"):
        os.makedirs(f"log/{combination_path}")

    total_defense = list(range(1, 16))
    total_exp_normal = 0
    total_exp_large = 0
    left_exp_normal = []
    left_exp_large = []
    fk = flowkey.Flowkey()
    for defense_nos in combinations(total_defense, n_comb):
        is_bf = [fk.get_flowkey(x)[4] for x in defense_nos]
        if (n_comb - sum(is_bf) >= 2 or n_comb == 1) and not any(n in defense_nos for n in exclude_exp):
            filename = "_".join([str(x) for x in defense_nos])
            if not file_exists(f"results/{combination_path}", filename):
                if not any(n in defense_nos for n in large_exp):
                    left_exp_normal.append(filename)
                else:
                    left_exp_large.append(filename)

            if not any(n in defense_nos for n in large_exp):
                total_exp_normal += 1
            else:
                total_exp_large += 1
    print(f"Left normal experiments: {len(left_exp_normal)}/{total_exp_normal}\t{left_exp_normal}", flush=True)
    print(f"Left large experiments: {len(left_exp_large)}/{total_exp_large}\t{left_exp_large}", flush=True)

def main(n_comb: int, exp_name: str):
    combination_path = f"combination {n_comb} {exp_name}/" if exp_name else f"combination {n_comb}/"
    if not os.path.exists(f"results/{combination_path}"):
        os.makedirs(f"results/{combination_path}")
    if not os.path.exists(f"log/{combination_path}"):
        os.makedirs(f"log/{combination_path}")

    with ProcessPoolExecutor(max_workers=10) as pool_normal, ProcessPoolExecutor(max_workers=2) as pool_large:  # pool_normal expected mem_usage < 600MB, pool_large expected mem_usage < 1100MB
        total_defense = list(range(1, 16))
        total_exp_normal = 0
        total_exp_large = 0
        left_exp_normal = []
        left_exp_large = []
        fk = flowkey.Flowkey()
        futures = {}
        for defense_nos in combinations(total_defense, n_comb):
            is_bf = [fk.get_flowkey(x)[4] for x in defense_nos]
            if (n_comb - sum(is_bf) >= 2 or n_comb == 1) and not any(n in defense_nos for n in exclude_exp):
                filename = "_".join([str(x) for x in defense_nos])
                if not file_exists(f"results/{combination_path}", filename):
                    param_filename = f"{combination_path}{filename}"
                    if not any(n in defense_nos for n in large_exp):
                        left_exp_normal.append(filename)
                        futures[pool_normal.submit(run_program, param_filename, exp_name)] = filename, "normal"
                    else:
                        left_exp_large.append(filename)
                        futures[pool_large.submit(run_program, param_filename, exp_name)] = filename, "large"

                if not any(n in defense_nos for n in large_exp):
                    total_exp_normal += 1
                else:
                    total_exp_large += 1
        print(f"Left normal experiments: {len(left_exp_normal)}/{total_exp_normal}\t{left_exp_normal}", flush=True)
        print(f"Left large experiments: {len(left_exp_large)}/{total_exp_large}\t{left_exp_large}", flush=True)

        for future in as_completed(futures):
            filename, pool_type = futures[future]
            print(f"Finished experiment {filename} ({pool_type})", flush=True)
            if pool_type == "large":
                left_exp_large.remove(filename)
            elif pool_type == "normal":
                left_exp_normal.remove(filename)
            print(f"Left normal experiments: {len(left_exp_normal)}/{total_exp_normal}\t{left_exp_normal}", flush=True)
            print(f"Left large experiments: {len(left_exp_large)}/{total_exp_large}\t{left_exp_large}", flush=True)

if __name__ == '__main__':
    n_comb = 1
    exp_name = "no elephant"

    print(f"Started experiment combination {n_comb} {exp_name} at {datetime.now()}", flush=True)
    start_time = time.time()
    # exp_count(n_comb, exp_name)
    main(n_comb, exp_name)
    elapsed_time = time.time() - start_time
    hours, rem = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(rem, 60)
    print(f"Execution time: {int(hours):02}:{int(minutes):02}:{seconds:05.2f}", flush=True)
    print(f"Finished experiment combination {n_comb} {exp_name} at {datetime.now()}", flush=True)
