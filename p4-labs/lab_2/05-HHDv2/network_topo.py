from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('info')
net.setCompiler(p4rt=True)
net.execScript('python control_plane.py', reboot=True)

# Network definition
net.addP4RuntimeSwitch('s1')
net.addP4RuntimeSwitch('s2')
net.setP4SourceAll('./hdd_v2.p4')

net.addHost('h1')
net.addHost('h2')

net.addLink("h1", "s1", port2=1)
net.addLink("s1", "s2", port1=2, port2=2)
net.addLink("s2", "h2", port1=1)

# Assignment strategy
net.mixed()

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()
net.startNetwork()