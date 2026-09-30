# How Hindsight elevated my random forest predictions

Machine learning is great at finding anomalies, but it's terrible at providing context.

When I set out to build an autonomous AI SOC agent, I knew I didn't want to rely on static firewall rules. I wanted the system to detect novel threats on the fly. I built a Python daemon that uses Scapy to sniff live network traffic, extracts flow metrics, and passes them into a Random Forest classifier trained on the CIC-IDS2017 dataset. 

Within a few days, the model was reliably flagging Port Scans, DDoS attempts, and Brute Force attacks. I wired the output to an LLM to generate mitigation reports. It felt like a success, until I let it run on a live network.

The problem? The Random Forest model was stateless. It would confidently predict a "Brute Force" attack with 98% accuracy based on a 3-second traffic window, but it had no idea if this was the first time the IP had attacked, or the fiftieth. 

To turn mathematical predictions into actionable security intelligence, the agent needed [Vectorize agent memory](https://vectorize.io/what-is-agent-memory). Here is how I bridged the gap between statistical ML predictions and long-term semantic context using Hindsight.

## The Limits of Stateless ML

A Random Forest classifier looks at discrete features. In my pipeline, it analyzes `Flow Duration`, `Total Fwd Packets`, and `Flow Bytes/s`. 

```python
# ml/threat_predictor.py
def predict_threat(event_dict):
    # Apply Preprocessing Pipeline
    X_processed = _preprocessor.transform(df_event)
        
    # Predict Class and Confidence
    predicted_label = _model.predict(X_processed)[0]
    probabilities = _model.predict_proba(X_processed)[0]
    class_index = list(_model.classes_).index(predicted_label)
    confidence_score = float(probabilities[class_index])
    
    return {
        "predicted_class": predicted_label,
        "confidence_score": confidence_score
    }
```

This is incredibly fast, but it treats every event as an isolated occurrence. If a benign scanner trips the threshold, the LLM treats it with the same severity as a persistent, multi-day state-sponsored attack. The ML model provides *detection*, but it fails to provide *investigation*.

## Injecting Semantic Memory

I realized that instead of trying to force temporal logic into my Random Forest model (which requires complex recurrent architectures like LSTMs), I could keep the ML layer fast and stateless, and push the temporal tracking to an external memory store.

I integrated Hindsight, a specialized memory server for AI agents. You can view the project at the [Hindsight GitHub](https://github.com/vectorize-io/hindsight).

Whenever the LLM generates a mitigation report for an ML prediction, we permanently retain that report in Hindsight:

```python
# ml/hindsight_client.py
def retain_incident(self, incident_data):
    """Store an incident report into Hindsight Memory."""
    payload = {
        "text": incident_data.get('Incident Summary', 'No summary provided.'),
        "metadata": {
            "source_ip": incident_data.get('Source IP'),
            "threat_type": incident_data.get('Threat Type')
        }
    }
    
    requests.post(
        f"{self.server_url}/v1/memory/retain",
        json=payload
    )
```

Now, when the Random Forest model flags a new flow, we intercept the pipeline. Before we ask the LLM to analyze the ML prediction, we query Hindsight to see if this specific attacker has a history.

```python
def recall_ip_history(self, source_ip):
    """Retrieve all past incidents related to a specific IP."""
    response = requests.get(
        f"{self.server_url}/v1/memory/recall",
        params={"metadata_filter": f"source_ip:{source_ip}"}
    )
    return response.json().get("results", [])
```

## Bridging Math and Context

The combination of the two systems completely elevated the agent's capabilities. 

The Random Forest model acts as a highly efficient, stateless trigger. It processes thousands of packets a second with minimal CPU overhead. When it catches an anomaly, Hindsight steps in to provide the narrative. 

The LLM now receives a prompt that looks like this:
*The ML model detected a Brute Force attack with 99% confidence. Hindsight memory shows this IP previously attempted a Port Scan two days ago and was temporarily rate-limited.*

With both statistical evidence and historical context, the agent makes flawless mitigation decisions, immediately escalating the response to a permanent firewall block. 

If you are building machine learning pipelines that feed into LLMs, don't try to build state into your models. Keep your models fast and stateless, and rely on a dedicated memory layer for context. You can read more about how this specific memory architecture works in the [Hindsight docs](https://hindsight.vectorize.io/). Combining the two is the key to building autonomous agents that actually work in the real world.
