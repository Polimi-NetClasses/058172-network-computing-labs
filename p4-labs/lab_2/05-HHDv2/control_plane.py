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

controller.table_clear('ipv4_lpm')

controller.table_add('ipv4_lpm', 'ipv4_forward', ['10.0.1.1/32'], ['00:00:0a:00:01:01', '1'])
controller.table_add('ipv4_lpm', 'ipv4_forward', ['10.0.2.2/32'], ['00:00:00:02:01:00', '2'])

controller.table_set_default('ipv4_lpm', 'drop')

controller = controllers['s2']     

controller.table_clear('ipv4_lpm')

controller.table_add('ipv4_lpm', 'ipv4_forward', ['10.0.2.2/32'], ['00:00:0a:00:02:02', '1'])
controller.table_add('ipv4_lpm', 'ipv4_forward', ['10.0.1.1/32'], ['00:00:00:02:01:00', '2'])

controller.table_set_default('ipv4_lpm', 'drop')