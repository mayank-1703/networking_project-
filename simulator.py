import random
import pandas as pd


class TrafficSimulator:

    def random_ip(self):
        return ".".join(
            str(random.randint(1, 255))
            for _ in range(4)
        )

    def generate_normal(self):

        return {
            "duration": random.randint(50, 300),
            "packets": random.randint(20, 500),
            "bytes": random.randint(1000, 50000),
            "connections": random.randint(1, 10),
            "packet_rate": random.randint(10, 100),
            "byte_rate": random.randint(100, 5000),
            "protocol": random.choice(
                ["TCP", "UDP", "HTTP"]
            ),
            "src_ip": self.random_ip(),
            "label": "Normal"
        }

    def generate_ddos(self):

        return {
            "duration": random.randint(1, 20),
            "packets": random.randint(5000, 50000),
            "bytes": random.randint(
                500000,
                5000000
            ),
            "connections": random.randint(
                100,
                1000
            ),
            "packet_rate": random.randint(
                1000,
                10000
            ),
            "byte_rate": random.randint(
                100000,
                1000000
            ),
            "protocol": random.choice(
                ["TCP", "UDP"]
            ),
            "src_ip": self.random_ip(),
            "label": "DDoS"
        }

    def generate_portscan(self):

        return {
            "duration": random.randint(5, 60),
            "packets": random.randint(
                500,
                5000
            ),
            "bytes": random.randint(
                5000,
                50000
            ),
            "connections": random.randint(
                50,
                500
            ),
            "packet_rate": random.randint(
                200,
                1000
            ),
            "byte_rate": random.randint(
                1000,
                10000
            ),
            "protocol": "TCP",
            "src_ip": self.random_ip(),
            "label": "PortScan"
        }

    def generate_bruteforce(self):

        return {
            "duration": random.randint(
                20,
                200
            ),
            "packets": random.randint(
                1000,
                10000
            ),
            "bytes": random.randint(
                50000,
                500000
            ),
            "connections": random.randint(
                20,
                200
            ),
            "packet_rate": random.randint(
                100,
                2000
            ),
            "byte_rate": random.randint(
                10000,
                50000
            ),
            "protocol": "TCP",
            "src_ip": self.random_ip(),
            "label": "BruteForce"
        }

    def generate_dataset(
        self,
        samples=5000
    ):

        data = []

        generators = [
            self.generate_normal,
            self.generate_ddos,
            self.generate_portscan,
            self.generate_bruteforce
        ]

        for _ in range(samples):

            attack = random.choice(
                generators
            )

            data.append(
                attack()
            )

        return pd.DataFrame(data)

    def save_dataset(
        self,
        filename="network_traffic.csv",
        samples=5000
    ):

        df = self.generate_dataset(
            samples
        )

        df.to_csv(
            filename,
            index=False
        )

        return df

    def generate_live_traffic(self):

        attack = random.choice(
            [
                self.generate_normal,
                self.generate_ddos,
                self.generate_portscan,
                self.generate_bruteforce
            ]
        )

        return attack()


if __name__ == "__main__":

    simulator = TrafficSimulator()

    df = simulator.save_dataset(
        "network_traffic.csv",
        5000
    )

    print(df.head())
    print("\nDataset Created")