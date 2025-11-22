#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from random import choice, randint
from string import ascii_lowercase, digits
from functools import lru_cache
import crcmod
import numpy as np

import sys
from numbers import Number
from collections import deque
from collections.abc import Set, Mapping
ZERO_DEPTH_BASES = (str, bytes, Number, range, bytearray)
def getsize(obj_0):
    """Recursively iterate to sum size of object & members."""
    _seen_ids = set()
    def inner(obj):
        obj_id = id(obj)
        if obj_id in _seen_ids:
            return 0
        _seen_ids.add(obj_id)
        size = sys.getsizeof(obj)
        if isinstance(obj, ZERO_DEPTH_BASES):
            pass # bypass remaining control flow and return
        elif isinstance(obj, (tuple, list, Set, deque)):
            size += sum(inner(i) for i in obj)
        elif isinstance(obj, Mapping) or hasattr(obj, 'items'):
            size += sum(inner(k) + inner(v) for k, v in getattr(obj, 'items')())
        # Check for custom object instances - may subclass above too
        if hasattr(obj, '__dict__'):
            size += inner(vars(obj))
        if hasattr(obj, '__slots__'): # can have __slots__ with __dict__
            size += sum(inner(getattr(obj, s)) for s in obj.__slots__ if hasattr(obj, s))
        return size
    return inner(obj_0)

def gen_string(length: int) -> list[str]:
    chars = ascii_lowercase + digits
    lst = [''.join(choice(chars) for _ in range(32)) for _ in range(length)]
    return lst

def print_cms(cms: list[list[int]]):
    for i in cms:
        for j in i:
            print(j, end='\t')
        print()

def list_difference(list1: list, list2: list) -> tuple[list, list]:
    set1 = set(list1)
    set2 = set(list2)
    difference1 = set1.difference(set2)
    difference2 = set2.difference(set1)
    return list(difference1), list(difference2)

def list_elementwise_add(list1: list[int], list2: list[int]) -> list[int]:
    if len(list1) != len(list2):
        raise ValueError(f"Two lists have different sizes: {len(list1)} and {len(list2)}")
    return [x + y for x, y in zip(list1, list2)]

def list_elementwise_sub(list1: list[int], list2: list[int]) -> list[int]:
    if len(list1) != len(list2):
        raise ValueError(f"Two lists have different sizes: {len(list1)} and {len(list2)}")
    return [x - y for x, y in zip(list1, list2)]

def get_first_from_second(tuples_list: list[tuple], second_value):
    for first, second in tuples_list:
        if second == second_value:
            return first
    return None

def get_key_from_value(d, value):
    for key, val in d.items():
        if val == value:
            return key
    return None

def crc_polynomial(num: int, degree: int):
    if degree not in [8, 16, 24, 32, 64]:
        raise ValueError(f"The degree of the polynomial must be 8, 16, 24, 32 or 64: {degree}")

    result = []
    shifted = 1 << degree
    while (len(set(result)) != num):
        result = [shifted + randint(0, shifted-1) for _ in range(num)]
    return result

# Tofino usually uses CRC32 for hash functions
polynomial = [0x104C11DB7, 0x11EDC6F41, 0x1A833982B, 0x1741B8CD7]   # crc32, crc32c, crc32d, crc32k
# seed(1234)
# polynomial = crc_polynomial(N_HASH, CRC_POLYNOMIAL_DEGREE)
crc_funcs = [crcmod.mkCrcFun(polynomial[depth], initCrc=0xFFFFFFFF, xorOut=0xFFFFFFFF, rev=True) for depth in range(4)]
@lru_cache(maxsize=60000)
def hash_crc(element: bytes, depth: int) -> int:
    return crc_funcs[depth](element)

def allocate_slice(register_size: int, is_bf: list[bool]) -> list[int]:
    total = register_size - 2*sum(is_bf)
    num_cms = len(is_bf) - sum(is_bf)
    if num_cms == 0:
        if len(is_bf) > 16:
            raise ValueError(f"Register is too small to accomodate all tasks: {is_bf}")
        return [2]*len(is_bf)

    divided = [total/num_cms] * num_cms
    rounded = [round(x) for x in divided]
    diff = list_elementwise_sub(divided, rounded)
    while sum(rounded) < total:
        index = np.argmax(diff)
        rounded[index] += 1
        diff[index] -= 1
    while sum(rounded) > total:
        index = np.argmin(diff)
        rounded[index] -= 1
        diff[index] += 1
    if min(rounded) < 2:
        raise ValueError(f"Register is too small to accomodate all tasks: {is_bf}")

    for i in range(len(is_bf)):
        if is_bf[i]:
            rounded.insert(i, 2)
    return rounded
