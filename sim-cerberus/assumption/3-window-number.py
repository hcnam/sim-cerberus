#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np

threshold = 400
window_length = 8

def find_window_number():
    for i in np.linspace(0, window_length, num=threshold)[:-1]:
        if blocked_on_send_x_pps_at_y_second_for_z_seconds(threshold/window_length, i, window_length):
            return round(window_length/i)

def blocked_on_send_x_pps_at_y_second_for_z_seconds(x: float, y: float, z: float) -> bool:
    return 8/3-8/800 <= y <= 8/3+8/800

print(find_window_number())
