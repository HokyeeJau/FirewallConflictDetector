# -*- coding:utf-8 -*-
# author: hokyeejau
# date: 2023/03/21/
import os
import csv
import json
import argparse

from tqdm import trange
from itertools import product
from typing import List, Dict, Union, Optional


idx2conflict: Dict[int, str] = {
    0: 'none',
    1: 'identity',
    2: 'properset',
    3: 'superset',
    4: 'intersection',
    5: 'overauthorization'
}

conflict2idx: Dict[str, int] = {conflict: idx for idx, conflict in idx2conflict.items()}


class Policy:

    __slots__ = ['pid', 'protocol', 'inactive', 'action', 'dst_ip_start', 'dst_ip_end', 'dst_port_start', 'dst_port_end',
                 'src_ip_start', 'src_ip_end', 'src_port_start', 'src_port_end']

    def __init__(self, pid: str, protocol: str,
                 src_ip: Dict[str, int],
                 src_port: Dict[str, Union[int, str]],
                 dst_ip: Dict[str, int],
                 dst_port: Dict[str, Union[int, str]],
                 inactive: bool, action: str):

        self.pid: int = pid
        self.protocol: str = self.transform_protocol(protocol)
        self.inactive: bool = inactive
        self.action: bool = self.boolean_action(action)

        self.src_ip_start: int = src_ip['start']
        self.src_ip_end: int = src_ip['end']

        self.src_port_start: int = src_port['start']
        self.src_port_end: int = src_port['end']

        self.dst_ip_start: int = dst_ip['start']
        self.dst_ip_end: int = dst_ip['end']

        self.dst_port_start: int = dst_port['start']
        self.dst_port_end: int = dst_port['end']


    def boolean_action(self, action: str) -> bool:
        if action.lower() in ['f', '0', 'n', 'no', 'deny', 'reject']:
            return False
        return True

    def transform_protocol(self, protocol):
        if protocol.lower() in ['*', 'any', '0']:
            return 'any'
        else:
            return protocol


def find_relation_between_ranges(start_1: int, end_1: int, start_2: int, end_2: int) -> int:

    if start_1 == end_1 and start_2 == end_2:
        if start_1 == start_2:
            return 1
        else:
            return 0

    if start_1 < start_2:
        if end_1 >= end_2:
            return 3
        else:
            return 4
    if start_1 > start_2:
        if end_1 > end_2:
            return 4
        else:
            return 2
    if start_1 == start_2:
        if end_1 < end_2:
            return 2
        elif end_1 == end_2:
            return 1
        else:
            return 3

    return 0


def find_relation_of_relations(relation_1: int, relation_2: int) -> int:
    if not relation_1 or not relation_2:
        return 0

    if relation_1 == 1 or relation_2 == 1:
        return relation_1 * relation_2

    if relation_1 == 4 or relation_2 == 4:
        return 4

    if relation_1 == relation_2:
        return relation_1
    else:
        return 4


def action_relation_pack(src_ip, dst_ip, src_port, dst_port, relation, action, conflict) -> Dict[str, Union[int, str]]:
    return {'src_ip_rel': src_ip, 'dst_ip_rel': dst_ip, 'src_port_rel': src_port, 'dst_port_rel': dst_port,
            'relation_rel': relation, 'action_rel': action, 'conflict': conflict}


def _detect_conflict_between_pure_(policy_1: Policy, policy_2: Policy) -> Dict[str, Union[int, str]]:
    # protocol -> src_ip -> src_port -> dst_ip -> dst_port

    if policy_1.protocol != policy_2.protocol:
        return action_relation_pack(0, 0, 0, 0, 0, 0, '')

    if policy_1.protocol == policy_2.protocol:
        protocol_relation = 1
    elif policy_1.protocol == 'any' and policy_2.protocol != 'any':
        protocol_relation = 3
    else:
        protocol_relation = 2

    src_ip_relation: int = find_relation_between_ranges(
        policy_1.src_ip_start, policy_1.src_ip_end,
        policy_2.src_ip_start, policy_2.src_ip_end)

    # src_port_relation: int = find_relation_between_ranges(
    #     policy_1.src_port_start, policy_2.src_port_end,
    #     policy_2.src_port_start, policy_2.src_port_end)

    dst_ip_relation: int = find_relation_between_ranges(
        policy_1.dst_ip_start, policy_1.dst_ip_end,
        policy_2.dst_ip_start, policy_2.dst_ip_end)

    dst_port_relation: int = find_relation_between_ranges(
        policy_1.dst_port_start, policy_1.dst_port_end,
        policy_2.dst_port_start, policy_2.dst_port_end)

    if src_ip_relation * dst_ip_relation * dst_port_relation == 0:
        return action_relation_pack(0, 0, 0, 0, 0, 0, '')

    relation: int = find_relation_of_relations(dst_ip_relation, src_ip_relation)
    relation: int = find_relation_of_relations(relation, protocol_relation)
    # relation: int = find_relation_of_relations(relation, src_port_relation)
    relation: int = find_relation_of_relations(relation, dst_port_relation)
    action: int = int(policy_2.action == policy_1.action)

    if action:
        if relation == 3:
            conflict = 'redundant'
        elif relation == 2 or relation == 1:
            conflict = 'redundant'
        else:
            conflict = 'correlated'
    else:
        if relation == 1:
            conflict = 'shadowed'
        elif relation == 2:
            conflict = 'general'
        elif relation == 3:
            conflict = 'shadowed'
        elif relation == 4:
            conflict = 'correlated'
        else:
            return action_relation_pack(0, 0, 0, 0, 0, 0, '')
    pack = action_relation_pack(src_ip_relation, dst_ip_relation, 1, dst_port_relation, relation, action, conflict)
    return pack


def start_end_pack(start, end) -> Dict[str, Union[str, int]]:
    return {'start': start, 'end': end}


def find_range(stream: str) -> Dict[str, str]:
    if '-' in stream:
        temp: List[str] = stream.split('-')
        return start_end_pack(temp[0], temp[1])
    else:
        return start_end_pack(stream, stream)


def parse_ip_groups(ip: str) -> List[Dict[str, str]]:
    if ip.lower() in ['any', '0.0.0.0', '*.*.*.*']:
        return [start_end_pack('0.0.0.0', '255.255.255.255')]

    _ip_groups: List[str] = ip.replace(" ", "").split(',')
    ip_groups: List[Dict[str, str]] = list()

    for _ip in _ip_groups:
        ip_groups.append(find_range(_ip))

    return ip_groups


def parse_port_groups(port: str, if_prot: bool) -> List[Dict[str, Union[str, int]]]:
    if port.lower() == 'any':
        pack = start_end_pack(0, 65535)
        if if_prot:
            pack['protocol'] = 'any'
        return [pack]

    _port_groups: List[str] = port.replace(' ', '').split(',')
    port_groups: List[Dict[str, Union[str, int]]] = list()
    temp: Optional[str] = None

    for _port in _port_groups:
        if if_prot:
            temp = _port.split('_')
            _port = temp[1]

        pack: Dict[str, Union[int, str]] = find_range(_port)
        pack['start'] = int(pack['start'])
        pack['end'] = int(pack['end'])

        if if_prot:
            pack['protocol'] = temp[0]

        port_groups.append(pack)

    return port_groups


def parse_fields(policy: List[str], config) -> Dict[str, List[Dict[str, Union[str, int]]]]:

    src_ip: List[Dict[str, str]] = parse_ip_groups(policy[config.src_ip])
    dst_ip: List[Dict[str, str]] = parse_ip_groups(policy[config.dst_ip])

    src_port: List[Dict[str, Union[str, int]]] = parse_port_groups(policy[config.src_port], config.protocol < 0)
    dst_port: List[Dict[str, Union[str, int]]] = parse_port_groups(policy[config.dst_port], config.protocol < 0)

    return {
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port
    }


def decimalize(ip_group: Dict[str, str]) -> Dict[str, int]:
    def _decimalize_(ip_addr: str) -> int:
        ip_spaces: List[str] = ip_addr.strip().split('.')
        binary_spaces: List[str] = [bin(int(i))[2:].zfill(8) for i in ip_spaces]
        binary_stream: str = ''.join(binary_spaces)
        integers: int = int(binary_stream, base=2)
        return integers
    return dict(start=_decimalize_(ip_group['start']), end=_decimalize_(ip_group['end']))


def detect_conflicts_between_policies(policy_1: List[str], policy_2: List[str], config) -> List[Dict[str, int]]:
    """
    IP
    1. 'ANY'
    2. an address
    3. address range
    4. address groups
    
    Port
    1. 'ANY'
    2. a port
    3. port range
    4. port groups

    Protocol-Port
    1. 'ANY'
    2. protocol + a port
    3. protocol + ports
    """

    conflicts: List[Dict[str, Union[int, str]]] = list()

    socket_1: Dict[str, List[Dict[str, Union[str, int]]]] = parse_fields(policy_1, config)
    socket_2: Dict[str, List[Dict[str, Union[str, int]]]] = parse_fields(policy_2, config)

    print(policy_1[config.id], policy_2[config.id])

    if config.protocol >= 0:
        protocol_1: Optional[str] = policy_1[config.protocol]
        protocol_2: Optional[str] = policy_2[config.protocol]

        for src_ip_1, src_ip_2 in product(socket_1['src_ip'], socket_2['src_ip']):
            for src_port_1, src_port_2 in product(socket_1['src_port'], socket_2['src_port']):
                for dst_ip_1, dst_ip_2 in product(socket_1['dst_ip'], socket_2['dst_port']):
                    for dst_port_1, dst_port_2 in product(socket_1['dst_port'], socket_2['dst_port']):
                        p1 = Policy(pid=policy_1[config.id], protocol=protocol_1,
                                    src_ip=decimalize(src_ip_1), src_port=src_port_1,
                                    dst_ip=decimalize(dst_ip_1), dst_port=dst_port_1,
                                    inactive=policy_1[config.inactive], action=policy_1[config.action]
                                    )
                        p2 = Policy(pid=policy_2[config.id], protocol=protocol_2,
                                    src_ip=decimalize(src_ip_2), src_port=src_port_2,
                                    dst_ip=decimalize(dst_ip_2), dst_port=dst_port_2,
                                    inactive=policy_2[config.inactive], action=policy_2[config.action]
                                    )
                        conflict: Dict[str, Union[int, str]] = _detect_conflict_between_pure_(p1, p2)
                        conflict['pre'] = p1.pid
                        conflict['sub'] = p2.pid
                        if conflict['conflict']:
                            conflict[
                                'pre_src_socket'] = f"{src_ip_1['start']}-{src_ip_1['end']}:{src_port_1['start']}-{src_port_1['end']}"
                            conflict[
                                'pre_dst_socket'] = f"{dst_ip_1['start']}-{dst_ip_1['end']}:{dst_port_1['start']}-{dst_port_1['end']}"
                            conflict[
                                'sub_src_socket'] = f"{src_ip_2['start']}-{src_ip_2['end']}:{src_port_2['start']}-{src_port_2['end']}"
                            conflict[
                                'sub_dst_socket'] = f"{dst_ip_2['start']}-{dst_ip_2['end']}:{dst_port_2['start']}-{dst_port_2['end']}"
                            conflict['protocol'] = f"pre: {p1.protocol}, sub: {p2.protocol}"
                            conflict['action'] = f"pre: {policy_1[config.action]}, sub: {policy_2[config.action]}"
                            conflicts.append(conflict)
    else:

        # return len(list(product(socket_1['src_ip'], socket_2['src_ip']))) + \
        #        len(list(product(socket_1['src_port'], socket_2['src_port']))) + \
        #        len(list(product(socket_1['dst_ip'], socket_2['dst_ip']))) + \
        #        len(list(product(socket_1['dst_port'], socket_2['dst_port'])))

        for src_ip_1, src_ip_2 in product(socket_1['src_ip'], socket_2['src_ip']):
            for src_port_1, src_port_2 in product(socket_1['src_port'], socket_2['src_port']):
                for dst_ip_1, dst_ip_2 in product(socket_1['dst_ip'], socket_2['dst_ip']):
                    for dst_port_1, dst_port_2 in product(socket_1['dst_port'], socket_2['dst_port']):
                        p1 = Policy(pid=policy_1[config.id], protocol=dst_port_1['protocol'],
                                    src_ip=decimalize(src_ip_1), src_port=src_port_1,
                                    dst_ip=decimalize(dst_ip_1), dst_port=dst_port_1,
                                    inactive=policy_1[config.inactive], action=policy_1[config.action]
                                    )
                        p2 = Policy(pid=policy_2[config.id], protocol=dst_port_2['protocol'],
                                    src_ip=decimalize(src_ip_2), src_port=src_port_2,
                                    dst_ip=decimalize(dst_ip_2), dst_port=dst_port_2,
                                    inactive=policy_2[config.inactive], action=policy_2[config.action]
                                    )
                        conflict: Dict[str, Union[int, str]] = _detect_conflict_between_pure_(p1, p2)
                        conflict['pre'] = p1.pid
                        conflict['sub'] = p2.pid
                        print(conflict)

                        if conflict['conflict']:
                            conflict[
                                'pre_src_socket'] = f"{src_ip_1['start']}-{src_ip_1['end']}:{src_port_1['start']}-{src_port_1['end']}"
                            conflict[
                                'pre_dst_socket'] = f"{dst_ip_1['start']}-{dst_ip_1['end']}:{dst_port_1['start']}-{dst_port_1['end']}"
                            conflict[
                                'sub_src_socket'] = f"{src_ip_2['start']}-{src_ip_2['end']}:{src_port_2['start']}-{src_port_2['end']}"
                            conflict[
                                'sub_dst_socket'] = f"{dst_ip_2['start']}-{dst_ip_2['end']}:{dst_port_2['start']}-{dst_port_2['end']}"
                            conflict['protocol'] = f"pre: {p1.protocol}, sub: {p2.protocol}"
                            conflict['action'] = f"pre: {policy_1[config.action]}, sub: {policy_2[config.action]}"

                            conflicts.append(conflict)
    return conflicts


def check_overauthorization(policy: List[str], config) -> bool:
    src_ip = policy[config.src_ip].lower() in ['any', '0.0.0.0', '*.*.*.*']
    dst_ip = policy[config.dst_ip].lower() in ['any', '0.0.0.0', '*.*.*.*']

    dst_port = policy[config.dst_port].lower() in ['any', '*']

    if not config.private_cloud:
        return (src_ip and dst_ip) or dst_port
    else:
        return src_ip or dst_ip or dst_port


def detect_partial_conflicts(policy_1: List[str], subsequent_policy_list: List[List[str]], config):
    conflicts: List[Dict[str, int]] = list()

    for policy_2 in subsequent_policy_list:
        conflicts += detect_conflicts_between_policies(policy_1, policy_2, config)

    if len(conflicts):
        with open(os.path.join(config.cdir, f'{policy_1[config.id]}.json'), 'w+') as f:
            json.dump(conflicts, f)


def main(config):
    # process_pool = Pool(config.workers)

    if config.test:
        _reader = [
            ['1', '', '', '', '140.192.37.20', 'ANY', '', '*.*.*.*', '', 'tcp_80', 'deny'],
            ['2', '', '', '', '140.192.37.0-140.192.37.255', 'ANY', '', '*.*.*.*', '', 'tcp_80', 'accept'],
            ['3', '', '', '', '*.*.*.*', 'ANY', '', '140.192.37.40', '', 'tcp_80', 'accept'],
            ['4', '', '', '', '140.192.37.0-140.192.37.255', 'ANY', '', '140.192.37.40', '', 'tcp_80', 'deny'],
            ['5', '', '', '', '140.192.37.30', 'ANY', '', '*.*.*.*', '', 'tcp_21', 'deny'],
            ['6', '', '', '', '140.192.37.0-140.192.37.255', 'ANY', '', '*.*.*.*', '', 'tcp_21', 'accept'],
            ['7', '', '', '', '140.192.37.0-140.192.37.255', 'ANY', '', '140.192.37.40', '', 'tcp_21', 'accept'],
            ['8', '', '', '', '*.*.*.*', 'ANY', '', '140.192.37.40', '', 'tcp_21', 'accept'],
            ['9', '', '', '', '*.*.*.*', 'ANY', '', '*.*.*.*', '', 'tcp_0-65535', 'deny'],
            ['10', '', '', '', '140.192.37.0-140.192.37.255', 'ANY', '', '*.*.*.*', '', 'udp_53', 'accept'],
            ['11', '', '', '', '*.*.*.*', 'ANY', '', '140.192.37.0-140.192.37.255', '', 'udp_53', 'accept'],
            ['12', '', '', '', '*.*.*.*', 'ANY', '', '*.*.*.*', '', 'udp_0-65535', 'deny'],
        ]
    else:
        with open(config.fpath, 'r') as csvfile:
            _reader = list(csv.reader(csvfile))[config.first_policy:]

    overauthorization: int = 0
    overauthorized_list: List[str] = list()

    disable: int = 0
    disable_list: List[str] = list()

    reader: List[List[str]] = list()

    for i in range(config.first_policy, len(_reader)):
        if check_overauthorization(_reader[i], config):
            overauthorized_list.append(_reader[i][config.id])
            overauthorization += 1
        elif _reader[i][config.inactive]:
            disable_list.append(_reader[i][config.id])
            disable += 1
        else:
            reader.append(_reader[i])

    with open(config.oa, 'w') as f:
        f.write(", ".join(overauthorized_list))

    with open(config.disable, 'w') as f:
        f.write(", ".join(disable_list))

    pbar = trange(len(reader)-1)
    for i in pbar:
        print(reader[i], reader[i+1])
        detect_partial_conflicts(reader[i], reader[i+1:], config)


def sum(config):

    from glob import glob
    paths: List[str] = glob(os.path.join(config.cdir, '*.json'))

    conflicts: Dict[str, Union[int, List[str]]] = dict()
    keys: List[str] = ['redundant', 'shadowed', 'general', 'correlated']

    conflicts['total'] = 0

    for key in keys:
        conflicts[key] = 0
        conflicts[f'{key}_list'] = list()

    conflicts['redundant'] = 0

    for path in paths:
        with open(path, 'r') as cf:
            data: List[Dict[str, Union[int, str]]] = json.load(cf)

        for c in data:
            ctype: str = c['conflict']
            conflicts['total'] += 1
            conflicts[ctype] += 1
            conflicts[f'{ctype}_list'].append(f"{c['pre']}->{c['sub']}")

    with open(config.report, 'w+') as f:
        f.write(f"Total: {conflicts['total']}\n")

        for key in keys:
            f.write(f"\t{key.capitalize()}: {conflicts[key]}\n")
            for id_pair in conflicts[f"{key}_list"]:
                f.write(f'\t\t{id_pair}\n')


def clear_conflict(config):
    from glob import glob
    paths: List[str] = glob(os.path.join(config.cdir, '*.json'))
    for path in paths:
        os.remove(path)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    # columns of fields
    parser.add_argument('--id', type=int, default=0,
                        help='column of id, default 0')
    parser.add_argument('--inactive', type=int, default=2,
                        help='column of inactive, default 2')
    parser.add_argument('--src_ip', type=int, default=4,
                        help='column of source ip addresses, default 4')
    parser.add_argument('--src_port', type=int, default=5,
                        help='column of source ports, default 5')
    parser.add_argument('--dst_ip', type=int, default=7,
                        help='column of destination ip addresses, default 7')
    parser.add_argument('--dst_port', type=int, default=9,
                        help='column of destination ports, default 9')
    parser.add_argument('--protocol', type=int, default=-1,
                        help='column of protocol, default -1 (combined with dst_port)')
    parser.add_argument('--action', type=int, default=10,
                        help='column of action, default 10')

    # overall configurations
    parser.add_argument('--test', type=int, default=1,
                        help='test samples shown in the paper')
    parser.add_argument('--sum', type=int, default=1,
                        help='if summarize the conflict reports under cdir')
    parser.add_argument('--fpath', type=str, default='firewall_strategy.csv',
                        help='file(.csv) path containing resolved firewall rules')
    parser.add_argument('--cdir', type=str, default='xconflicts/',
                        help='directory for holding conflict reports')
    parser.add_argument('--first_policy', type=int, default=0,
                        help='the first line of policies in csv, default 1')
    parser.add_argument('--private_cloud', type=int, default=1,
                        help='if the firewall is belonging to private cloud')

    # filenames
    parser.add_argument('--oa', type=str, default='xoverauthorization1.txt')
    parser.add_argument('--disable', type=str, default='xdisable.txt')
    parser.add_argument('--report', type=str, default='xreport.txt')

    config = parser.parse_args()

    try:
        os.makedirs(config.cdir)
    except:
        pass

    clear_conflict(config)
    main(config)

    if config.sum:
        sum(config)

