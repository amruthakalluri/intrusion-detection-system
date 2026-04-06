import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Load dataset
data = pd.read_csv("data.csv")

# Features (input)
X = data[["duration", "failed_logins", "requests"]]

# Labels (output)
y = data["label"]

# Train model
model = RandomForestClassifier()
model.fit(X, y)

print("✅ Model trained successfully!")

# Test prediction
sample = [[20, 6, 25]]  # duration, failed_logins, requests
prediction = model.predict(sample)

print("Prediction:", prediction[0])