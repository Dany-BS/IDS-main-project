import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

# Features we can reliably extract using Scapy
SCAPY_FEATURES = [
    'protocol_type',     # Can get from IP.proto
    'service',           # Can determine from port numbers
    'flag',             # Can get TCP flags
    'src_bytes',        # Can get packet lengths
    'dst_bytes',        # Can get packet lengths
    'land',             # Can check if src_ip == dst_ip
    'wrong_fragment',   # Can check IP fragments
    'urgent',           # Can get TCP urgent flag
    'count',            # Can count connections
    'srv_count',        # Can count service connections
    'serror_rate',      # Can detect SYN errors
    'srv_serror_rate',  # Can detect SYN errors per service
    'rerror_rate',      # Can detect REJ errors
    'srv_rerror_rate',  # Can detect REJ errors per service
    'same_srv_rate',    # Can calculate from connection records
    'diff_srv_rate',    # Can calculate from connection records
    'dst_host_count',   # Can count connections to dst host
    'dst_host_srv_count' # Can count service connections to dst host
]

def load_and_preprocess_data():
    # Load the KDD dataset
    print("Loading dataset...")
    data = pd.read_csv("KDDTrain+.txt")
    
    # Assign column names
    columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 
              'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
              'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
              'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
              'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
              'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
              'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
              'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
              'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
              'outcome', 'level']
    data.columns = columns
    
    # Print unique values for categorical features
    print("\nUnique values in categorical features:")
    print("protocol_type:", data['protocol_type'].unique())
    print("service:", data['service'].unique())
    print("flag:", data['flag'].unique())
    
    # Select only features we can extract using Scapy
    X = data[SCAPY_FEATURES]
    
    # Convert categorical variables
    categorical_features = ['protocol_type', 'service', 'flag']
    X = pd.get_dummies(X, columns=categorical_features)
    
    print("\nFeatures after one-hot encoding:")
    print(X.columns.tolist())
    
    # Print sample data
    print("\nSample data (first row):")
    print(X.iloc[0])
    
    # Create binary labels (normal = 0, attack = 1)
    y = (data['outcome'] != 'normal').astype(int)
    
    # Print label distribution
    print("\nLabel distribution:")
    print(y.value_counts())
    
    return X, y

def evaluate_classification(model, name, X_train, X_test, y_train, y_test):
    # Calculate training and test accuracy
    train_accuracy = accuracy_score(y_train, model.predict(X_train))
    test_accuracy = accuracy_score(y_test, model.predict(X_test))
    
    print(f"\nModel Evaluation - {name}")
    print("-" * 40)
    print(f"Training Accuracy: {train_accuracy:.4f}")
    print(f"Testing Accuracy:  {test_accuracy:.4f}")
    
    # Make predictions on test set
    y_pred = model.predict(X_test)
    
    # Calculate additional metrics
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    
    # Print classification report
    print("\nDetailed Classification Report:")
    print("-" * 40)
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
    
    # Create confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    cm_display = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Normal', 'Attack'])
    
    # Plot confusion matrix
    plt.figure(figsize=(10, 8))
    cm_display.plot(cmap='Blues', values_format='d')
    plt.title(f'Confusion Matrix - {name}')
    plt.grid(False)
    plt.show()

def train_model(X, y):
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale the features
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train),
        columns=X_train.columns
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test),
        columns=X_test.columns
    )
    
    # Print scaled feature ranges
    print("\nScaled feature ranges:")
    print("Min:", X_train_scaled.min().min())
    print("Max:", X_train_scaled.max().max())
    
    # Train Random Forest
    print("\nTraining Random Forest model...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train_scaled, y_train)
    
    # Evaluate model
    evaluate_classification(rf_model, "Random Forest", X_train_scaled, X_test_scaled, y_train, y_test)
    
    # Print feature importances
    importances = pd.DataFrame({
        'feature': X.columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    print("\nTop 10 most important features:")
    print(importances.head(10))
    
    return rf_model, scaler, X.columns

def save_model_info(model, scaler, feature_names):
    # Save model, scaler, and feature names together
    model_info = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names
    }
    joblib.dump(model_info, 'scapy_model.pkl')
    
    print(f"\nModel and feature information saved as 'scapy_model.pkl'")
    print(f"Number of features: {len(feature_names)}")

if __name__ == "__main__":
    # Load and preprocess data
    X, y = load_and_preprocess_data()
    
    # Train model
    model, scaler, feature_names = train_model(X, y)
    
    # Save model and feature information
    save_model_info(model, scaler, feature_names) 