####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

import json
from router import Router
from packet import Packet

INFINITY = 16


class DVrouter(Router):
    """Distance vector routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        # port -> {'endpoint': endpoint, 'cost': cost}
        self.ports = {}
        # neighbor -> {dst: cost}
        self.neighbor_dvs = {}
        # dst -> cost
        self.dv = {self.addr: 0}
        # dst -> next_hop_neighbor
        self.next_hops = {}
        # dst -> port
        self.forwarding_table = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            if packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                self.send(out_port, packet)
        else:
            try:
                received_vector = json.loads(packet.content)
            except Exception:
                return

            neighbor = packet.src_addr
            if self.neighbor_dvs.get(neighbor) != received_vector:
                self.neighbor_dvs[neighbor] = received_vector
                self.recompute_routes()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.ports[port] = {'endpoint': endpoint, 'cost': cost}
        self.recompute_routes()
        self.broadcast_routes()

    def handle_remove_link(self, port):
        """Handle removed link."""
        if port in self.ports:
            endpoint = self.ports[port]['endpoint']
            del self.ports[port]
            if endpoint in self.neighbor_dvs:
                del self.neighbor_dvs[endpoint]
            self.recompute_routes()
            self.broadcast_routes()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.broadcast_routes()

    def recompute_routes(self):
        """Recompute distance vector and forwarding table using Bellman-Ford."""
        old_dv = dict(self.dv)
        old_next_hops = dict(self.next_hops)

        # Collect all known destinations
        destinations = set()
        destinations.add(self.addr)
        for info in self.ports.values():
            destinations.add(info['endpoint'])
        for n_dv in self.neighbor_dvs.values():
            destinations.update(n_dv.keys())
        destinations.update(self.dv.keys())

        new_dv = {self.addr: 0}
        new_next_hops = {}
        new_forwarding_table = {}

        for dst in destinations:
            if dst == self.addr:
                continue

            best_cost = INFINITY
            best_port = None
            best_neighbor = None

            # Try routing through each directly connected active port
            for port in sorted(self.ports.keys()):
                info = self.ports[port]
                neighbor = info['endpoint']
                link_cost = info['cost']

                if dst == neighbor:
                    cand_cost = link_cost
                elif neighbor in self.neighbor_dvs and dst in self.neighbor_dvs[neighbor]:
                    cand_cost = link_cost + self.neighbor_dvs[neighbor][dst]
                else:
                    cand_cost = INFINITY

                if cand_cost < best_cost:
                    best_cost = cand_cost
                    best_port = port
                    best_neighbor = neighbor
                elif cand_cost == best_cost and best_cost < INFINITY:
                    # Prefer existing next hop to prevent unnecessary route flapping
                    if self.next_hops.get(dst) == neighbor:
                        best_port = port
                        best_neighbor = neighbor

            new_dv[dst] = min(best_cost, INFINITY)
            if best_cost < INFINITY:
                new_next_hops[dst] = best_neighbor
                new_forwarding_table[dst] = best_port

        self.dv = new_dv
        self.next_hops = new_next_hops
        self.forwarding_table = new_forwarding_table

        if self.dv != old_dv or self.next_hops != old_next_hops:
            self.broadcast_routes()

    def broadcast_routes(self, target_port=None):
        """Send distance vector to neighbors using split horizon with poisoned reverse."""
        for port, info in self.ports.items():
            if target_port is not None and port != target_port:
                continue
            neighbor = info['endpoint']

            # Poison reverse: if we route to dst through neighbor, advertise INFINITY
            vector = {}
            for dst, cost in self.dv.items():
                if dst == self.addr:
                    vector[dst] = 0
                elif self.next_hops.get(dst) == neighbor and dst != neighbor:
                    vector[dst] = INFINITY
                else:
                    vector[dst] = min(cost, INFINITY)

            content = json.dumps(vector)
            pkt = Packet(Packet.ROUTING, self.addr, neighbor, content=content)
            self.send(port, pkt)

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return f"DVrouter(addr={self.addr}, table={self.forwarding_table})"
