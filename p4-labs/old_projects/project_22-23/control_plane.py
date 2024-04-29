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

controller.table_add("vip_to_backend", "update_backend_info", ["2"], [
                     "10.0.0.2", '8000', '00:00:0a:00:00:02'])
controller.table_add("vip_to_backend", "update_backend_info", ["3"], [
                     "10.0.0.3", '8000', '00:00:0a:00:00:03'])
controller.table_add("vip_to_backend", "update_backend_info", ["4"], [
                     "10.0.0.4", '8000', '00:00:0a:00:00:04'])
controller.table_add("vip_to_backend", "update_backend_info", ["5"], [
                     "10.0.0.5", '8000', '00:00:0a:00:00:05'])

controller.table_add("virtual_ip", "is_virtual_ip",
                     ["10.0.1.2", '3000'], ["1"])

controller.table_add("backend_to_vip", "backend_to_vip_conversion", [
                     "10.0.0.1/24"], ["10.0.1.2", '3000', "00:0c:29:c0:94:bf"])
