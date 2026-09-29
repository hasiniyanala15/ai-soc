import pandas as pd
import numpy as np
import os

DATASET_PATH = "data/cic_ids2017_synthetic.csv"

def generate_synthetic_cic_ids2017(num_records=10000):
    """
    Generates a synthetic dataset mimicking the CIC-IDS2017 dataset.
    This avoids downloading a 400MB CSV while allowing us to build the pipeline.
    """
    np.random.seed(42)
    
    # 1. Define distributions for different attack classes
    classes = ["Benign", "Brute Force", "DoS", "PortScan"]
    probabilities = [0.70, 0.10, 0.10, 0.10] # Imbalanced like real world
    
    target_labels = np.random.choice(classes, size=num_records, p=probabilities)
    
    data = []
    for label in target_labels:
        if label == "Benign":
            row = [
                np.random.normal(5000, 1000),   # Flow Duration
                np.random.randint(2, 10),       # Total Fwd Packets
                np.random.randint(2, 10),       # Total Backward Packets
                np.random.normal(1000, 200),    # Total Length of Fwd Packets
                80,                             # Destination Port (HTTP)
                6,                              # Protocol (TCP)
                np.random.normal(10, 2),        # Flow Bytes/s
                np.random.randint(0, 2)         # Failed Logins (Fake custom feature)
            ]
        elif label == "Brute Force":
            row = [
                np.random.normal(50000, 5000),  # Longer flows
                np.random.randint(20, 50),      
                np.random.randint(20, 50),
                np.random.normal(5000, 500),    
                22,                             # SSH
                6,                              # TCP
                np.random.normal(50, 10),       
                np.random.randint(5, 15)        # High failed logins
            ]
        elif label == "DoS":
            row = [
                np.random.normal(100, 10),      # Extremely fast flows
                np.random.randint(100, 1000),   # Flood of packets
                0,                              # Very few replies
                np.random.normal(50000, 5000),  
                80,                             
                6,                              
                np.random.normal(5000, 1000),   # Huge bandwidth  
                0
            ]
        elif label == "PortScan":
            row = [
                np.random.normal(10, 2),        # Instant drop
                1,                              # 1 packet
                1,                              
                0,                              
                np.random.randint(1, 65535),    # Random ports
                6,                              
                0,                              
                0
            ]
            
        # Introduce some missing/infinity values to simulate real messy data
        if np.random.rand() < 0.01:
            row[0] = np.nan # Missing duration
        if np.random.rand() < 0.01:
            row[6] = np.inf # Infinite bytes/s
            
        data.append(row)
        
    columns = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Destination Port", "Protocol",
        "Flow Bytes/s", "Failed Logins"
    ]
    
    df = pd.DataFrame(data, columns=columns)
    df['Label'] = target_labels
    
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    print(f"Generated synthetic dataset with {len(df)} records at {DATASET_PATH}")
    return DATASET_PATH

def load_dataset():
    """Loads the dataset from the CSV file."""
    if not os.path.exists(DATASET_PATH):
        print("Dataset not found. Generating synthetic dataset...")
        generate_synthetic_cic_ids2017()
        
    df = pd.read_csv(DATASET_PATH)
    return df

if __name__ == "__main__":
    df = load_dataset()
    print("Dataset Info:")
    print(df.info())
    print("\nClass Distribution:")
    print(df['Label'].value_counts())
