#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from common import *
import cms as cms

class ControlPlane:
    def __init__(self, n_task: int, counter_size_per_tasks: list[int], array_size_per_tasks: list[int], n_hash: int, n_window: int = 2):
        self.cms = [[cms.CountMinSketch(counter_size_per_tasks[i], 2**array_size_per_tasks[i], n_hash) for i in range(n_task)] for _ in range(n_window)]

    def read(self, task_id: int, element, current_window: int) -> list[int]:
        return self.cms[(current_window-1) % 2][task_id].read(element)

    def co_monitoring(self, task_id: int, element, overflowed_data: list[int], operation: str, current_window: int) -> list[int]:
        # Manage CMS in Control Plane
        # Write overflow values from data plane to CMS
        read_value = []
        for i in range(self.cms[current_window][task_id].depth):
            hash_value = hash_crc(element, i) % self.cms[current_window][task_id].cms_array_size
            if operation == "plus" or operation == "minus":
                self.cms[current_window][task_id].cms[i][hash_value] += overflowed_data[i]
            elif operation == "setbitTrue":
                self.cms[current_window][task_id].cms[i][hash_value] |= overflowed_data[i]
            elif operation == "setbitFalse":
                self.cms[current_window][task_id].cms[i][hash_value] = overflowed_data[i]
            else:
                raise ValueError(f"Not a valid operation: {operation}")
            result = min(self.cms[current_window][task_id].cms[i][hash_value], self.cms[current_window][task_id].max) # Saturate the result (no overflow)
            self.cms[current_window][task_id].cms[i][hash_value] = result
            read_value.append(result)
        return read_value

    def send_to_dataplane(self, window: int, task_id: int, slicing: int) -> list[list[int]]:
        sending_data = [[0] * self.cms[window][task_id].cms_array_size for _ in range(self.cms[window][task_id].depth)]
        for i in range(self.cms[window][task_id].depth):
            for j in range(self.cms[window][task_id].cms_array_size):
                sending_data[i][j] = self.cms[window][task_id].cms[i][j] % (2**slicing)
                self.cms[window][task_id].cms[i][j] = self.cms[window][task_id].cms[i][j] // (2**slicing)
        return sending_data

    def receive_from_dataplane(self, window: int, task_id: int, slicing: int, received_data: list[list[int]]):
        for i in range(self.cms[window][task_id].depth):
            for j in range(self.cms[window][task_id].cms_array_size):
                self.cms[window][task_id].cms[i][j] = min(self.cms[window][task_id].cms[i][j] * (2**(-slicing)) + received_data[i][j], self.cms[window][task_id].max)

    def receive_from_dataplane_elephant(self, task_id: int, received_data: dict, current_window: int):
        for element in received_data:
            for i in range(self.cms[current_window][task_id].depth):
                hash_value = hash_crc(element, i) % self.cms[current_window][task_id].cms_array_size
                self.cms[current_window][task_id].cms[i][hash_value] += received_data[element][i]
                result = min(self.cms[current_window][task_id].cms[i][hash_value], self.cms[current_window][task_id].max) # Saturate the result (no overflow)
                self.cms[current_window][task_id].cms[i][hash_value] = result
