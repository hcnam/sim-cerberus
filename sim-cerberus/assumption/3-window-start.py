#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np

threshold = 400
window_length = 8

def find_window_start_not_used():
    return time_until_blocked_on_send_x_pps(threshold/window_length) - window_length

def find_window_start():
    for i in np.linspace(0, window_length, num=threshold)[:-1]:
        if blocked_on_send_x_pps_at_y_second_for_z_seconds(threshold/window_length, i, window_length):
            return i

def time_until_blocked_on_send_x_pps(x: float) -> float:
    return 8.2

def blocked_on_send_x_pps_at_y_second_for_z_seconds(x: float, y: float, z: float) -> bool:
    return 8/400*35 <= y <= 8/400*36

print(find_window_start_not_used())
print(find_window_start())
