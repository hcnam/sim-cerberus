#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import register as reg

class DataPlane:
    def __init__(self, n_task_per_reg: list[int], slice_per_registers: list[list[int]], array_size_per_registers: list[list[int]], elephant_array_sizes: list[list[int]], n_register: int, n_hash: int, n_window: int = 2):
        self.register = [[reg.Register(n_task_per_reg[i], slice_per_registers[i], array_size_per_registers[i], elephant_array_sizes[i], n_hash) for i in range(n_register)] for _ in range(n_window)]

    def update_register(self, reg_index: int, task_index: int, operation: str, element, value: int, current_window: int) -> tuple[list[int], list[int]]:
        return self.register[current_window][reg_index].update_cms(task_index, operation, element, value)

    def read(self, reg_index: int, task_index: int, element, current_window: int) -> list[int]:
        return self.register[(current_window-1) % 2][reg_index].read(task_index, element)

    def read_all(self, reg_index: int, task_index: int, element) -> int:
        return sum([min(self.register[i][reg_index].read(task_index, element)) for i in range(2)])

    def change_top_k(self, reg_index: int, task_index: int, inserted_keys: list, evicted_keys: list, current_window: int) -> dict:
        return self.register[current_window][reg_index].change_top_k(task_index, inserted_keys, evicted_keys)
