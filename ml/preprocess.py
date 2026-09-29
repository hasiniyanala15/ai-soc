import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer

# Step 4: Feature Engineering - Define the exact features we will use
# We explicitly avoid using the target 'Label' or anything unavailable at prediction time
FEATURES = [
    "Flow Duration", 
    "Total Fwd Packets", 
    "Total Backward Packets",
    "Total Length of Fwd Packets", 
    "Destination Port", 
    "Protocol",
    "Flow Bytes/s", 
    "Failed Logins"
]

TARGET_COLUMN = "Label"

def clean_data(df):
    """
    Step 3: Dataset Preparation - Clean the dataset.
    Replaces infinite values with NaN so they can be imputed properly.
    Removes exact duplicates.
    """
    print("--- Dataset Preparation ---")
    print(f"Initial records: {len(df)}")
    
    # Identify and drop duplicates
    duplicates = df.duplicated().sum()
    print(f"Found {duplicates} duplicate records. Removing...")
    df = df.drop_duplicates().reset_index(drop=True)
    
    # Replace Infinite values with NaN
    # Many network datasets (like CIC-IDS2017) have division by zero (Flow Bytes/s = Infinity)
    inf_count = np.isinf(df.select_dtypes(include=[np.number])).values.sum()
    print(f"Found {inf_count} infinite values. Converting to NaN...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Identify Missing Values
    missing_count = df.isna().sum().sum()
    print(f"Found {missing_count} missing (NaN) values.")
    print(f"Records after cleaning: {len(df)}")
    
    return df

def get_preprocessor():
    """
    Step 5: Data Leakage Prevention
    We define a scikit-learn Pipeline. 
    This pipeline will ONLY be fitted on the TRAINING data later.
    It imputes missing values with the median, and scales features to zero-mean.
    """
    # SimpleImputer fills NaN values with the median of the column
    # StandardScaler normalizes the data so large byte counts don't overpower small packet counts
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, FEATURES)
        ],
        remainder='drop' # Drop any columns not explicitly defined in FEATURES
    )
    
    return preprocessor

if __name__ == "__main__":
    import sys
    import os
    # Add parent directory to path to import dataset_loader
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ml.dataset_loader import load_dataset
    
    df = load_dataset()
    df_clean = clean_data(df)
    
    print("\n--- Target Label Distribution ---")
    print(df_clean[TARGET_COLUMN].value_counts())
