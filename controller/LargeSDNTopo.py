from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class LargeSDNTopo(Topo):

    def build(self):

        # -------------------------
        # CORE SWITCHES
        # -------------------------
        core1 = self.addSwitch('s1')
        core2 = self.addSwitch('s2')
        core3 = self.addSwitch('s3')
        core4 = self.addSwitch('s4')

        # -------------------------
        # AGGREGATION SWITCHES
        # -------------------------
        agg1 = self.addSwitch('s5')
        agg2 = self.addSwitch('s6')
        agg3 = self.addSwitch('s7')
        agg4 = self.addSwitch('s8')
        agg5 = self.addSwitch('s9')
        agg6 = self.addSwitch('s10')

        # -------------------------
        # ACCESS SWITCHES
        # -------------------------
        acc1 = self.addSwitch('s11')
        acc2 = self.addSwitch('s12')
        acc3 = self.addSwitch('s13')
        acc4 = self.addSwitch('s14')
        acc5 = self.addSwitch('s15')
        acc6 = self.addSwitch('s16')
        acc7 = self.addSwitch('s17')
        acc8 = self.addSwitch('s18')

        # -------------------------
        # HOSTS
        # -------------------------
        hosts = []
        for i in range(1, 33):
            hosts.append(self.addHost('h%s' % i))

        # -------------------------
        # CONNECT HOSTS TO ACCESS
        # -------------------------
        access_switches = [acc1, acc2, acc3, acc4, acc5, acc6, acc7, acc8]

        host_index = 0
        for sw in access_switches:
            for i in range(4):
                self.addLink(hosts[host_index], sw)
                host_index += 1

        # -------------------------
        # ACCESS → AGGREGATION
        # -------------------------
        self.addLink(acc1, agg1)
        self.addLink(acc1, agg2)

        self.addLink(acc2, agg1)
        self.addLink(acc2, agg2)

        self.addLink(acc3, agg2)
        self.addLink(acc3, agg3)

        self.addLink(acc4, agg3)
        self.addLink(acc4, agg4)

        self.addLink(acc5, agg4)
        self.addLink(acc5, agg5)

        self.addLink(acc6, agg5)
        self.addLink(acc6, agg6)

        self.addLink(acc7, agg3)
        self.addLink(acc7, agg6)

        self.addLink(acc8, agg2)
        self.addLink(acc8, agg5)

        # -------------------------
        # AGGREGATION → CORE
        # -------------------------
        self.addLink(agg1, core1)
        self.addLink(agg1, core2)

        self.addLink(agg2, core1)
        self.addLink(agg2, core3)

        self.addLink(agg3, core2)
        self.addLink(agg3, core4)

        self.addLink(agg4, core3)
        self.addLink(agg4, core4)

        self.addLink(agg5, core1)
        self.addLink(agg5, core4)

        self.addLink(agg6, core2)
        self.addLink(agg6, core3)

        # -------------------------
        # CORE REDUNDANCY
        # -------------------------
        self.addLink(core1, core2)
        self.addLink(core2, core3)
        self.addLink(core3, core4)
        self.addLink(core4, core1)

        # -------------------------
        # AGGREGATION CROSS LINKS
        # -------------------------
        self.addLink(agg1, agg2)
        self.addLink(agg3, agg4)
        self.addLink(agg5, agg6)

        # -------------------------
        # ACCESS CROSS LINKS
        # -------------------------
        self.addLink(acc1, acc2)
        self.addLink(acc3, acc4)
        self.addLink(acc5, acc6)
        self.addLink(acc7, acc8)


topos = {'custom': (lambda: LargeSDNTopo())}
