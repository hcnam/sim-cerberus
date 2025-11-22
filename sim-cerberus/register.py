#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from common import *
import cms as cms
import unittest

class Register:
    def __init__(self, n_task: int, counter_sizes: list[int], array_sizes: list[int], elephant_array_sizes: list[int], n_hash: int, counter_size: int = 32, cms_array_size: int = 16):
        self.counter_size = counter_size
        self.cms_array_size = 2**cms_array_size # Initial array size = 2**16
        self.n_task = n_task
        self.n_hash = n_hash
        self.cms = [cms.CountMinSketch(counter_sizes[i], 2**array_sizes[i], n_hash) for i in range(n_task)]
        # Note: we do not allow size change of elephant region for simplicity
        if elephant_array_sizes:
            self.elephant_region = [{} for _ in range(n_task)] # counter size is same as self.counter_size
            self.elephant_array_sizes = [2**elephant_array_sizes[i] for i in range(n_task)]
        else:
            self.elephant_region = []
            self.elephant_array_sizes = []
        # self.integrity_check()

    # Check if initial reigister size changed
    # def integrity_check(self):
    #     register_size = self.counter_size * self.cms_array_size
    #     used_size = 0
    #     for task in self.cms:
    #         used_size += (task.counter_size * task.cms_array_size)
    #     if used_size != register_size:
    #         raise ValueError(f"{used_size} is not equal to register size: {register_size}")

    def resize_cms(self, task_index: int, slicing: int, new_arr_size: int, control_plane_data: list[list[int]]) -> list[list[int]]:
        result = self.cms[task_index].resize_bucket(slicing, new_arr_size, control_plane_data)
        # print(result)
        return result

    def update_cms(self, task_index: int, operation: str, element, value: int) -> tuple[list[int], list[int]]:
        # Check elephant 
        # IF elephant -> update elephant -> (list[overflow], list[current_value])
        # ELSE -> update cms
        if self.is_elephant(task_index, element):
            return self.update_elephant(task_index, operation, element, value)

        if operation == "plus":
            return self.cms[task_index].plus(element, value)
        elif operation == "minus":
            return self.cms[task_index].minus(element, value)
        elif operation == "setbitTrue":
            return self.cms[task_index].setbit(element, value, True)
        elif operation == "setbitFalse":
            return self.cms[task_index].setbit(element, value, False)
        else:
            raise ValueError(f"Invalid operation type: {operation}")

    def update_elephant(self, task_index: int, operation: str, element, value: int) -> tuple[list[int], list[int]]:
        result = self.elephant_region[task_index][element]
        if operation == "plus":
            result += value
        elif operation == "minus":
            result -= value
        elif operation == "setbitTrue":
            result |= value
        elif operation == "setbitFalse":
            result = value
        else:
            raise ValueError(f"Invalid operation type: {operation}")
        self.elephant_region[task_index][element] = result % (2**(self.counter_size-1))
        overflow_value = [result // (2**(self.counter_size-1)) * (2**(self.counter_size-self.cms[task_index].counter_size))] * self.n_hash
        return overflow_value, self.read(task_index, element)

    def read(self, task_index: int, element) -> list[int]:
        read_value = self.cms[task_index].read(element)
        if self.is_elephant(task_index, element):
            read_value = [x + self.elephant_region[task_index][element] for x in read_value]
        return read_value

    def change_top_k(self, task_index: int, inserted_keys: list, evicted_keys: list) -> dict:
        result = {}
        for element in evicted_keys:
            read_value = self.elephant_region[task_index].pop(element)
            result[element] = self.cms[task_index].plus(element, read_value)

        for element in inserted_keys:
            self.elephant_region[task_index][element] = 0
        return result

    def is_elephant(self, task_index: int, element) -> bool:
        # Check if flow is elephant
        return self.elephant_region and element in self.elephant_region[task_index]


############################################
# Unit Test
############################################
class TestRegister(unittest.TestCase):
    def test_init(self):
        print("TEST INIT")
        n_task = 2
        counter_sizes = [16, 16]
        array_sizes = [4, 4]
        elephant_array_sizes = [2, 2]
        n_hash = 4
        reg = Register(n_task, counter_sizes, array_sizes, elephant_array_sizes, n_hash)
        for i in range(n_task):
            print(f"========== task {i} ==========")
            print_cms(reg.cms[i].cms)
            print(reg.elephant_region[i])
        print("\n\n")

if __name__ == '__main__':
    unittest.main()
