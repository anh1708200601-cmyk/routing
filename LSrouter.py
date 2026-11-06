####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

import json
import heapq
from router import Router
from packet import Packet


class LSrouter(Router):
    """Link state routing protocol implementation.

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
        # router sequence number
        self.seq = 0
        # origin -> {neighbor: cost}
        self.topology = {}
        # origin -> highest_seq
        self.received_seq = {}
        # origin -> (seq, {neighbor: cost})
        self.lsp_database = {}
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
                data = json.loads(packet.content)
                origin = data["origin"]
                seq = data["seq"]
                links = data["links"]
            except Exception:
                return

            # Ignore our own LSP that looped back
            if origin == self.addr:
                return

            if seq > self.received_seq.get(origin, -1):
                old_links = self.topology.get(origin)
                self.received_seq[origin] = seq
                self.topology[origin] = links
                self.lsp_database[origin] = (seq, links)

                # Recompute shortest paths if topology actually changed
                if old_links != links:
                    self.recompute_routes()

                # Flood LSP to all other neighbors
                for out_port in self.ports:
                    if out_port != port:
                        self.send_lsp(out_port, origin, seq, links)

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.ports[port] = {"endpoint": endpoint, "cost": cost}
        self.seq += 1

        my_links = {info["endpoint"]: info["cost"] for info in self.ports.values()}
        self.topology[self.addr] = my_links
        self.lsp_database[self.addr] = (self.seq, my_links)
        self.received_seq[self.addr] = self.seq
        self.recompute_routes()

        # Broadcast new LSP to all neighbors
        self.broadcast_lsp(self.addr, self.seq, my_links)

        # Synchronize database with the new neighbor on this port
        for origin, (seq, links) in self.lsp_database.items():
            if origin != self.addr:
                self.send_lsp(port, origin, seq, links)

    def handle_remove_link(self, port):
        """Handle removed link."""
        if port in self.ports:
            del self.ports[port]
            self.seq += 1

            my_links = {info["endpoint"]: info["cost"] for info in self.ports.values()}
            self.topology[self.addr] = my_links
            self.lsp_database[self.addr] = (self.seq, my_links)
            self.received_seq[self.addr] = self.seq
            self.recompute_routes()

            # Broadcast new link state without the removed link
            self.broadcast_lsp(self.addr, self.seq, my_links)

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.seq += 1

            my_links = {info["endpoint"]: info["cost"] for info in self.ports.values()}
            self.topology[self.addr] = my_links
            self.lsp_database[self.addr] = (self.seq, my_links)
            self.received_seq[self.addr] = self.seq

            self.broadcast_lsp(self.addr, self.seq, my_links)

    def send_lsp(self, port, origin, seq, links):
        """Send an LSP out of a specific port."""
        content = json.dumps({"origin": origin, "seq": seq, "links": links})
        endpoint = self.ports[port]["endpoint"]
        pkt = Packet(Packet.ROUTING, self.addr, endpoint, content=content)
        self.send(port, pkt)

    def broadcast_lsp(self, origin, seq, links):
        """Broadcast an LSP to all directly connected neighbors."""
        for port in self.ports:
            self.send_lsp(port, origin, seq, links)

    def recompute_routes(self):
        """Compute shortest paths using Dijkstra's algorithm."""
        dist = {}
        first_hop = {}
        pq = []

        dist[self.addr] = 0

        # Initialize directly connected active links from self.ports
        for port in sorted(self.ports.keys()):
            info = self.ports[port]
            neighbor = info["endpoint"]
            cost = info["cost"]
            if neighbor not in dist or cost < dist[neighbor]:
                dist[neighbor] = cost
                first_hop[neighbor] = port
                heapq.heappush(pq, (cost, neighbor, port))

        while pq:
            d, u, port = heapq.heappop(pq)

            if d > dist.get(u, float("inf")):
                continue

            neighbors = self.topology.get(u, {})
            for v, weight in neighbors.items():
                if v == self.addr:
                    continue
                # If v is a router in topology, enforce bidirectional link check
                if v in self.topology and u not in self.topology[v]:
                    continue

                new_dist = d + weight
                if new_dist < dist.get(v, float("inf")):
                    dist[v] = new_dist
                    first_hop[v] = port
                    heapq.heappush(pq, (new_dist, v, port))
                elif new_dist == dist.get(v, float("inf")) and v in self.forwarding_table:
                    if self.forwarding_table[v] == port:
                        first_hop[v] = port

        self.forwarding_table = first_hop

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return f"LSrouter(addr={self.addr}, table={self.forwarding_table})"
