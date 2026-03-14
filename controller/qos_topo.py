from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class FatTreeTopo(Topo):
    def build(self):
        # Create hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')

        # Create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        s8 = self.addSwitch('s8')
        s9 = self.addSwitch('s9')
        s10 = self.addSwitch('s10')

        # Add links between hosts and switches
        self.addLink(h1, s7)
        self.addLink(h2, s7)
        self.addLink(h3, s8)
        self.addLink(h4, s8)
        self.addLink(h5, s9)
        self.addLink(h6, s9)
        self.addLink(h7, s10)
        self.addLink(h8, s10)

        # Add links between lower layer switches and middle layer switches
        self.addLink(s7, s3)
        self.addLink(s4, s8)
        self.addLink(s9, s5)
        self.addLink(s6, s10)
        #__________________________________
        
        self.addLink(s3, s8)
        self.addLink(s4, s7)
        self.addLink(s6, s9)
        self.addLink(s5, s10)
   
        #__________________________
        # Add links between middle layer switches and upper layer switches
        self.addLink(s3, s1)
        self.addLink(s5, s1)
        self.addLink(s4, s2)
        self.addLink(s6, s2)

        #self.addLink(s1, s2)
        
# Register the custom topology
topos = {'custom': (lambda: FatTreeTopo())}
