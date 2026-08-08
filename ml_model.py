import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
class ThreatDetectionModel:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=512,
            random_state=42
        )
        self.protocol_encoder = LabelEncoder()
        self.label_encoder = LabelEncoder()
    def train(self):
        df = pd.read_csv(
            "network_traffic.csv"
        )
        df["protocol"] = (
            self.protocol_encoder.fit_transform(
                df["protocol"]
            )
        )
        df["label"] = (
            self.label_encoder.fit_transform(
                df["label"]
            )
        )
        X = df[
            [
                "duration",
                "packets",
                "bytes",
                "connections",
                "packet_rate",
                "byte_rate",
                "protocol"
            ]
        ]

        y = df["label"]

        X_train, X_test, y_train, y_test = (
            train_test_split(
                X,
                y,
                test_size=0.2,
                random_state=42
            )
        )

        self.model.fit(
            X_train,
            y_train
        )

        predictions = self.model.predict(
            X_test
        )

        accuracy = accuracy_score(
            y_test,
            predictions
        )

        print(
            f"Accuracy: {accuracy:.4f}"
        )

        joblib.dump(
            self.model,
            "attack_model.pkl"
        )

        joblib.dump(
            self.protocol_encoder,
            "protocol_encoder.pkl"
        )

        joblib.dump(
            self.label_encoder,
            "label_encoder.pkl"
        )

    def load(self):

        self.model = joblib.load(
            "attack_model.pkl"
        )

        self.protocol_encoder = (
            joblib.load(
                "protocol_encoder.pkl"
            )
        )

        self.label_encoder = (
            joblib.load(
                "label_encoder.pkl"
            )
        )

    def predict(self, data):

        protocol = (
            self.protocol_encoder.transform(
                [data["protocol"]]
            )[0]
        )

        features = [[
            data["duration"],
            data["packets"],
            data["bytes"],
            data["connections"],
            data["packet_rate"],
            data["byte_rate"],
            protocol
        ]]

        prediction = self.model.predict(
            features
        )[0]

        confidence = max(
            self.model.predict_proba(
                features
            )[0]
        )

        attack = (
            self.label_encoder
            .inverse_transform(
                [prediction]
            )[0]
        )

        return {
            "attack": attack,
            "confidence": round(
                confidence * 100,
                2
            )
        }


if __name__ == "__main__":

    detector = (
        ThreatDetectionModel()
    )

    detector.train()

    detector.load()

    sample = {
        "duration": 8,
        "packets": 1000,
        "bytes": 1000000,
        "connections": 509,
        "packet_rate": 4000,
        "byte_rate": 300003,
        "protocol": "UDP"
    }

    result = detector.predict(
        sample
    )

    print(result)