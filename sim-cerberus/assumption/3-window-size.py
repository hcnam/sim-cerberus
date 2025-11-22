#!/usr/bin/env python3
# -*- coding: utf-8 -*-

threshold = 400

def find_window_length(eps):
    low, high = 0.0, 1.0
    # 1. Exponential search to find an upper bound
    while not blocked_on_send_x_pps_for_y_seconds(high, threshold/high*2):
        low = high
        high *= 2.0

    # 2. Binary search within [low, high] until the range is within eps
    while low == 0.0 or (threshold/low - threshold/high) > eps:
        mid = (low + high) / 2.0
        if blocked_on_send_x_pps_for_y_seconds(mid, threshold/mid*2):
            high = mid
        else:
            low = mid

    return threshold/high, threshold/low

def blocked_on_send_x_pps_for_y_seconds(x: float, y: float) -> bool:
    return 4*2*x > threshold

print(find_window_length(0.1))
