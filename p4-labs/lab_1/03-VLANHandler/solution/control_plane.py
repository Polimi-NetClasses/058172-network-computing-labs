#!/usr/bin/env python3

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI


topo = load_topo('topology.json')
controllers = {}

for switch, data in topo.get_p4rtswitches().items():
    controllers[switch] = SimpleSwitchP4RuntimeAPI(data['device_id'], data['grpc_port'],
                                                  p4rt_path=data['p4rt_path'],
                                                  json_path=data['json_path'])

controller = controllers['s1']     

controller.table_clear('vlan_table')

controller.table_add('vlan_table', 'forward', ['2'], ['2'])
controller.table_add('vlan_table', 'forward', ['20'], ['2'])
controller.table_add('vlan_table', 'forward', ['3'], ['3'])
controller.table_add('vlan_table', 'forward', ['30'], ['3'])
controller.table_add('vlan_table', 'forward', ['4'], ['4'])
controller.table_add('vlan_table', 'forward', ['40'], ['4'])

controller.table_clear('port_to_vlan')
controller.table_add('port_to_vlan', 'add_vlan_hdr', ['2'], ['2'])
controller.table_add('port_to_vlan', 'add_vlan_hdr', ['3'], ['3'])
controller.table_add('port_to_vlan', 'add_vlan_hdr', ['4'], ['4'])
