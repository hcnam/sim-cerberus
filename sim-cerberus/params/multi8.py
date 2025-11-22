#!/usr/bin/env python3
# -*- coding: utf-8 -*-

KEY_TABLE = {
    0: "src_ip",
    1: "src_port",
    2: "dst_ip",
    3: "dst_port",
    4: "protocol"
}

TASK_MATCH_ACTION_TABLE = {
    # TASK_ID: {key: [src_ip, src_port, dst_ip, dst_port, protocol], action: [actions...], value: 1 or 0 (packetsize) }
    0 : { # ICMP flood
        "key": [None, None, "dst_ip", None, "ICMP"],
        "action": ["add"],
        "value": 1
    },
    1: {
        "key": [None, None, "dst_ip", "dst_port", None],
        "action": ["add"],
        "value": 1
    },
    2: {
        "key": [None, None, "dst_ip", None, "UDP"],
        "action": ["add"],
        "value": 0 # packet size
    },
    # TODO: Fill up left match-ation table
}

KEY_TASK_TABLE = {
    # TASK_ID : KEYS for key-feature pair
    0: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
    1: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
    2: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
    3: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
    4: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
    5: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
    6: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
    7: ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
}

# TASK_OP_TABLE = {
#     # TASK_ID : OPERATION
#     0: ["add", "minus"],
#     1: ["add"],
#     2: ["add"],
#     3: ["add"],
#     4: ["add"],
#     5: ["add"],
#     6: ["add"],
#     7: ["add"]
# }

REG_ALLOC_TABLE = {
    # TASK_ID : REG_ID
    0: 0, 
    1: 0,
    2: 0,
    3: 0,
    4: 1,
    5: 1,
    6: 1,
    7: 1,
}

REFRESH_CYCLE = 8
