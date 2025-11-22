#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from common import *
import unittest
from random import randint

class CountMinSketch:
    def __init__(self, counter_size: int, array_size: int, n_hash: int):
        self.counter_size = counter_size
        self.cms_array_size = array_size
        self.depth = n_hash
        self.max = 2**(self.counter_size-1) - 1
        # self.carry_bits = [[False] * self.cms_array_size for _ in range(self.depth)] # not used
        self.cms = [[0] * self.cms_array_size for _ in range(self.depth)]

    def operate(self, element, action) -> tuple[list[int], list[int]]:
        overflow_value = [0] * self.depth
        read_value = []
        for i in range(self.depth):
            hash_value = hash_crc(element, i) % self.cms_array_size
            result = action(self.cms[i][hash_value])
            self.cms[i][hash_value] = result % (2**(self.counter_size-1))
            overflow_value[i] = result // (2**(self.counter_size-1))
            # if overflow_value[i] != 0:
            #     self.carry_bits[i][hash_value] = True
            read_value.append(self.cms[i][hash_value])
        return overflow_value, read_value

    def plus(self, element, value: int = 1) -> tuple[list[int], list[int]]:
        return self.operate(element, lambda x : x + value)

    def minus(self, element, value: int) -> tuple[list[int], list[int]]:
        return self.operate(element, lambda x : x - value)

    def setbit(self, element, value: int, orbit: bool) -> tuple[list[int], list[int]]:
        def action(x):
            if orbit == True:
                return x | value
            else:
                return value
        return self.operate(element, action)

    def read(self, element) -> list[int]:
        read_value = []
        for i in range(self.depth):
            hash_value = hash_crc(element, i) % self.cms_array_size
            read_value.append(self.cms[i][hash_value])
        return read_value

    # upper: [[]] or list of upper bits received from control plane
    def resize_bucket(self, change_counter_size: int, new_array_size: int, upper: list[list[int]]) -> list[list[int]]:
        if new_array_size < 0:
            raise ValueError(f"New array size can't be negative: {new_array_size}")

        # change array size
        if new_array_size > self.cms_array_size:    # enlargement
            enlargement_ratio = new_array_size // self.cms_array_size
            if enlargement_ratio * self.cms_array_size != new_array_size:
                raise ValueError("New array size is not a multiple of the current array size!")
            enlarged_cms = [[0] * new_array_size for _ in range(self.depth)]
            # enlarged_carry_bits = [[False] * new_array_size for _ in range(self.depth)]

            for i in range(self.depth):
                for j in range(self.cms_array_size):
                    for k in range(enlargement_ratio):
                        # copy operation
                        enlarged_cms[i][j + (self.cms_array_size * k)] = self.cms[i][j]
                        # enlarged_carry_bits[i][j + (self.cms_array_size * k)] = self.carry_bits[i][j]

            self.cms_array_size = new_array_size
            self.cms = enlarged_cms
            # self.carry_bits = enlarged_carry_bits
        elif new_array_size < self.cms_array_size:  # compression
            compression_ratio = self.cms_array_size // new_array_size
            if compression_ratio * new_array_size != self.cms_array_size:
                raise ValueError("New array size is not divided by the current array size!")
            compressed_cms = [[0] * new_array_size for _ in range(self.depth)]
            # compressed_carry_bits = [[False] * new_array_size for _ in range(self.depth)]

            for i in range(self.depth):
                for j in range(new_array_size):
                    # max compression: B_i= max{A_1[j], A_2[j], ..., A_z[j]}
                    compressed_cms[i][j] = max(self.cms[i][row] for row in range(j, self.cms_array_size, new_array_size))
                    # for row in range(j, self.cms_array_size, new_array_size):
                        # compressed_carry_bits[i][j] |= self.carry_bits[i][row]

            self.cms_array_size = new_array_size
            self.cms = compressed_cms
            # self.carry_bits = compressed_carry_bits

        # change counter size
        new_counter_size = self.counter_size + change_counter_size
        result = [[]]
        if new_counter_size < 0:
            raise ValueError(f"New counter size can't be negative: {new_counter_size}")

        if new_counter_size > self.counter_size:
            # get upper bits from control plane
            for i in range(self.depth):
                for j in range(self.cms_array_size):
                    self.cms[i][j] = self.cms[i][j] + upper[i][j] * (2**(self.counter_size-1))

            self.counter_size = new_counter_size
            self.max = 2**(self.counter_size-1) - 1
        elif new_counter_size < self.counter_size:
            # send upper bits to control plane
            result = [[0] * self.cms_array_size for _ in range(self.depth)]

            for i in range(self.depth):
                for j in range(self.cms_array_size):
                    result[i][j] = self.cms[i][j] // (2**(new_counter_size-1))
                    self.cms[i][j] = self.cms[i][j] % (2**(new_counter_size-1))

            self.counter_size = new_counter_size
            self.max = 2**(self.counter_size-1) - 1
        return result   # [[]] or list of upper bits to send to control plane

############################################
# Unit Test
############################################
class TestCountMinSketch(unittest.TestCase):
    def test_init(self):
        print("TEST INIT")
        counter_size = 4
        array_size = 8
        n_hash = 4
        cms = CountMinSketch(counter_size, array_size, n_hash)
        print_cms(cms.cms)
        print("\n\n")

    def test_plus(self):
        print("TEST PLUS")
        counter_size = 9
        array_size = 8
        n_hash = 4
        cms = CountMinSketch(counter_size, array_size, n_hash)
        # Update the sketch with some elements
        elements_to_insert = [x.encode() for x in gen_string(20)]
        for element in elements_to_insert:
            rand_num = randint(1, 10)
            print(element, rand_num)
            cms.plus(element, rand_num)
        print_cms(cms.cms)
        print("\n\n")

    def test_read(self):
        print("TEST READ")
        counter_size = 9
        array_size = 16
        n_hash = 4
        cms = CountMinSketch(counter_size, array_size, n_hash)
        # Update the sketch with some elements
        elements_to_insert = [x.encode() for x in gen_string(20)]
        check_elements = {}
        for element in elements_to_insert:
            rand_num = randint(1, 10)
            # print(element, rand_num)
            check_elements[element] = rand_num
            cms.plus(element, rand_num)
        print("==========")
        print_cms(cms.cms)
        print("==========")
        # Estimate the frequency of some elements
        for element in elements_to_insert:
            print(f"{element} real {check_elements[element]}\tcms {min(cms.read(element))}")
        print("\n\n")

    def test_resize_array_size(self):
        print("TEST RESIZE ARRAY SIZE")
        counter_size = 9
        array_size = 8
        n_hash = 4
        cms = CountMinSketch(counter_size, array_size, n_hash)
        # Update the sketch with some elements
        elements_to_insert = [x.encode() for x in gen_string(20)]
        for element in elements_to_insert:
            rand_num = randint(1, 10)
            print(element, rand_num)
            cms.plus(element, rand_num)
        print("==========")
        print("Original")
        print_cms(cms.cms)

        print("==========")
        print("After Enlargement")
        enlarged_array_size = 16
        cms.resize_bucket(0, enlarged_array_size, [[]])
        print_cms(cms.cms)

        print("==========")
        print("After Compression")
        compressed_array_size = 8
        cms.resize_bucket(0, compressed_array_size, [[]])
        print_cms(cms.cms)
        print("\n\n")

    def test_resize_counter_size(self):
        print("TEST RESIZE COUNTER SIZE")
        counter_size = 9
        array_size = 8
        n_hash = 4
        cms = CountMinSketch(counter_size, array_size, n_hash)
        # Update the sketch with some elements
        elements_to_insert = [x.encode() for x in gen_string(20)]
        for element in elements_to_insert:
            rand_num = randint(1, 10)
            print(element, rand_num)
            cms.plus(element, rand_num)
        print("Original")
        print_cms(cms.cms)

        print("==========")
        print("After lengthening counter size")
        change_longer_counter_size = 2
        upper = [[randint(0, 3) for _ in range(array_size)] for _ in range (n_hash)]
        cms.resize_bucket(change_longer_counter_size, array_size, upper)
        print("Upper bits from control plane:")
        print_cms(upper)
        print("CMS:")
        print_cms(cms.cms)

        print("==========")
        print("After shortening counter size")
        change_shorter_counter_size = -2
        result = cms.resize_bucket(change_shorter_counter_size, array_size, [[]])
        print("Upper bits to control plane:")
        print_cms(result)
        print("CMS:")
        print_cms(cms.cms)

        print("\n\n")

if __name__ == '__main__':
    unittest.main()
