from fastapi import FastAPI
from algorithms import (
    build_demo_network,
    TopAttackers,
    AlertPriorityQueue
)
from simulator import TrafficSimulator
from database import (
    initialize_database,
    insert_traffic,
    insert_alert,
    get_alerts,
    get_traffic_logs
)
from ml_model import (
    ThreatDetectionModel
)


app = FastAPI(
    title="AI Network Threat Intelligence Platform"
)

initialize_database()

network = build_demo_network()

simulator = TrafficSimulator()

top_attackers = TopAttackers()

alert_queue = AlertPriorityQueue()

detector = ThreatDetectionModel()
detector.load()


@app.get("/")
def home():

    return {
        "message":
        "AI Network Threat Intelligence Platform Running"
    }


@app.get("/network")
def network_info():

    return network.graph


@app.get("/bfs/{start}")
def bfs(start: int):

    return {
        "traversal":
        network.bfs(start)
    }


@app.get("/dfs/{start}")
def dfs(start: int):

    return {
        "traversal":
        network.dfs(start)
    }


@app.get("/route")
def route(
    source: int,
    destination: int
):

    return network.dijkstra(
        source,
        destination
    )


@app.post("/generate")
def generate():

    traffic = simulator.generate_live_traffic()

    insert_traffic(traffic)

    prediction = detector.predict(
        traffic
    )

    if prediction["attack"] != "Normal":

        insert_alert(
            prediction["attack"],
            prediction["confidence"],
            traffic["src_ip"]
        )

        top_attackers.add_attack(
            traffic["src_ip"]
        )

        severity_map = {
            "DDoS": 10,
            "PortScan": 7,
            "BruteForce": 8
        }

        alert_queue.add_alert(
            prediction["attack"],
            severity_map.get(
                prediction["attack"],
                5
            ),
            traffic["src_ip"]
        )

    return {
        "traffic": traffic,
        "prediction": prediction
    }


@app.get("/alerts")
def alerts():

    return get_alerts()


@app.get("/traffic")
def traffic():

    return get_traffic_logs()


@app.get("/top-attackers")
def top_attackers_api():

    return top_attackers.get_top_attackers()


@app.get("/priority-alerts")
def priority_alerts():

    return alert_queue.get_all_alerts()