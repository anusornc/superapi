class HypercubeNode:
    def __init__(self, node_id, dimensions,super_api_nodes,validator_nodes):
        self.node_id = node_id
        self.dimensions = dimensions
        self.neighbors = []
        self.super_api_nodes = super_api_nodes
        self.validator_nodes = validator_nodes

    def get_node_by_id(self, node_id):
        all_nodes = self.super_api_nodes +  self.validator_nodes
        for node in all_nodes:
            if node.node_id == node_id:
                return node
        return None

    def add_neighbor(self, neighbor):
        self.neighbors.append(neighbor)

    def send_message(self, message, destination_node_id):
        shortest_path = self.find_shortest_path(destination_node_id)
        for node_id in shortest_path:
            node = self.get_node_by_id(self,node_id)
            node.receive_message(message)

    def receive_message(self, message):
        print(f"Node {self.node_id} received message: {message}")

    def find_shortest_path(self, destination_node_id):
        pass