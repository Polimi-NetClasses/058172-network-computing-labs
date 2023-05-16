from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('info')
net.setCompiler(p4rt=True)
net.execScript('python control_plane.py', reboot=True)

# Network definition
net.addP4RuntimeSwitch('s1')
net.setP4Source('s1', './l4_loadbalancer.p4')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')
net.addHost('h4')
net.addHost('h5')
net.addLink('s1', 'h1')
net.addLink('s1', 'h2')
net.addLink('s1', 'h3')
net.addLink('s1', 'h4')
net.addLink('s1', 'h5')

# Assignment strategy
net.l2()

# Nodes general options
net.addTaskFile('tasks.txt')
net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()
net.startNetwork()
