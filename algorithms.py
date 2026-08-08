import heapq
from collections import deque, Counter


class NetworkGraph:
    def __init__(self):
        self.graph = {}

    def add_router(self, router):
        if router not in self.graph:
            self.graph[router] = []

    def add_connection(self, u, v, weight):
        self.add_router(u)
        self.add_router(v)

        self.graph[u].append((v, weight))
        self.graph[v].append((u, weight))


    def remove_connection(self, u, v):
        self.graph[u] = [
            (node, w)
            for node, w in self.graph[u]
            if node != v
        ]

        self.graph[v] = [
            (node, w)
            for node, w in self.graph[v]
            if node != u
        ]

    def bfs(self, start):
        visited = set()
        queue = deque([start])
        traversal = []

        while queue:
            node = queue.popleft()

            if node in visited:
                continue

            visited.add(node)
            traversal.append(node)

            for neighbor, _ in self.graph[node]:
                if neighbor not in visited:
                    queue.append(neighbor)

        return traversal

    def dfs(self, start):
        visited = set()
        traversal = []

        def helper(node):
            visited.add(node)
            traversal.append(node)

            for neighbor, _ in self.graph[node]:
                if neighbor not in visited:
                    helper(neighbor)

        helper(start)

        return traversal

    def dijkstra(self, source, destination):
        distances = {
            node: float("inf")
            for node in self.graph
        }

        distances[source] = 0

        parent = {}

        pq = [(0, source)]

        while pq:
            curr_dist, node = heapq.heappop(pq)

            if curr_dist > distances[node]:
                continue

            if node == destination:
                break

            for neighbor, weight in self.graph[node]:

                new_dist = curr_dist + weight

                if new_dist < distances[neighbor]:

                    distances[neighbor] = new_dist
                    parent[neighbor] = node

                    heapq.heappush(
                        pq,
                        (new_dist, neighbor)
                    )

        if distances[destination] == float("inf"):
            return {
                "path": [],
                "cost": -1
            }

        path = []

        current = destination

        while current != source:
            path.append(current)
            current = parent[current]

        path.append(source)

        path.reverse()

        return {
            "path": path,
            "cost": distances[destination]
        }

    def connected_components(self):
        visited = set()
        components = []

        for node in self.graph:

            if node not in visited:

                component = []

                queue = deque([node])

                while queue:

                    curr = queue.popleft()
                    if curr in visited:
                        continue

                    visited.add(curr)
                    component.append(curr)

                    for neighbor, _ in self.graph[curr]:
                        if neighbor not in visited:
                            queue.append(neighbor)

                components.append(component)

        return components

    def affected_nodes(self, compromised_router):
        return self.bfs(compromised_router)


class AlertPriorityQueue:

    def __init__(self):
        self.heap = []

    def add_alert(
        self,
        threat_type,
        severity,
        source_ip
    ):

        heapq.heappush(
            self.heap,
            (
                -severity,
                threat_type,
                source_ip
            )
        )

    def get_alert(self):

        if not self.heap:
            return None

        severity, threat, ip = heapq.heappop(
            self.heap
        )

        return {
            "threat": threat,
            "severity": -severity,
            "source_ip": ip
        }

    def get_all_alerts(self):

        temp = []

        while self.heap:

            alert = self.get_alert()
            temp.append(alert)

        return temp


class TopAttackers:

    def __init__(self):
        self.counter = Counter()

    def add_attack(self, ip):
        self.counter[ip] += 1

    def get_top_attackers(
        self,
        top_n=10
    ):

        return heapq.nlargest(
            top_n,
            self.counter.items(),
            key=lambda x: x[1]
        )


def build_demo_network():

    network = NetworkGraph()

    connections = [
        (0, 1, 4),
        (0, 2, 2),
        (1, 3, 5),
        (2, 3, 1),
        (3, 4, 3),
        (4, 5, 2),
        (1, 5, 10),
        (5, 6, 4),
        (6, 7, 1),
        (7, 8, 2),
        (8, 9, 3),
        (3, 7, 5),
        (2, 8, 7)
    ]

    for u, v, w in connections:
        network.add_connection(
            u,
            v,
            w
        )

    return network