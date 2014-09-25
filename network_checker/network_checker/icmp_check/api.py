#    Copyright 2014 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import netaddr
import pcap
import scapy.all as scapy


class ICMPChecker(object):
    """Driver for ICMP net-check."""

    def __init__(self, **config):
        self.config = config
        self.listeners = []

    def listen(self):
        """Sets up pcap to listen to incomming ICMP echo requests."""

        icmp_filter = 'icmp and icmp[icmptype]=icmp-echoreply'

        for iface in self.config['ifaces']:
            listener = pcap.pcap(iface)
            listener.setfilter(icmp_filter)

            self.listeners.append(listener)

    def send(self):
        for net in self.config['networks']:
            for i in xrange(self.repeat):
                ipnet = netaddr.IPNetwork(net)

                bcast_addr = str(ipnet.broadcast)
                cookie = json.dumps({'cookie': self.config['cookie'],
                                     'net': net,
                                     'uid': self.config['uid']})

                scapy.send(IP(bcast_addr)/scapy.ICMP()/cookie)

    def test(self):
        raise NotImplemented("DEADBEEF")

    def get_info(self):
        messages = []
        for listener in self.listeners:
            for sock, pack in self.listener.readpkts():
                pack = scapy.Ether(pack)
                data, _ = pack[scapy.ICMP].extract_padding(
                        pack[scapy.ICMP].load)

                # Filter only ICMP requests from other nodes
                # with the cookie.
                if self.config['cookie'] in data and
                    self.config['uid'] not in data:

                    cookie = json.loads(data.decode())
                    messages.append(cookie)

        return list(set(messages))
