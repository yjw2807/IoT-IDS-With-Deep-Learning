# --- Install required libraries ---
!pip install scikit-learn imbalanced-learn seaborn --quiet

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (confusion_matrix, accuracy_score, precision_score, recall_score, 
                            f1_score, classification_report, roc_auc_score, roc_curve)
import joblib

# === STEP 1: Load data ===
df = pd.read_csv('/content/TONIOT.csv')



# === STEP 2: Remove identifier columns ===
encoders = {} # Dictionary to store encoders

for col in df.columns:
    if df[col].dtype == "object" and col not in ['label', 'type']:
        num_unique = df[col].nunique()
        if num_unique > min(30, len(df)//10):
            df = df.drop(columns=[col])
            continue
        
        # Create and save the encoder
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le # <--- SAVE THIS

# Later, save this dictionary
joblib.dump(encoders, 'encoders.pkl')

# === STEP 4: Drop any non-numeric columns left after encoding except 'label' and 'type' ===
for col in df.columns:
    if col not in ['label', 'type'] and not np.issubdtype(df[col].dtype, np.number):
        print(f"Column '{col}' still not numeric — dropping.")
        df = df.drop(columns=[col])

# === STEP 5: Impute missing values (mean for ALL except label/type) ===
for col in df.columns:
    if col not in ['label', 'type']:
        df[col] = pd.to_numeric(df[col], errors='coerce')  # Force to numeric blanks (NaN)
        df[col] = df[col].fillna(df[col].mean())

# === STEP 6: Features and labels ===
X = df.drop(['label', 'type'], axis=1)
y = df['label']

# === STEP 7: Train-test split (80-20, stratified) ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# === STEP 8: SMOTE ===
smote = SMOTE(random_state=42, k_neighbors=3)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

# === STEP 9: Scaling ===
scaler = StandardScaler()
X_train_bal = scaler.fit_transform(X_train_bal)
X_test = scaler.transform(X_test)

# === STEP 10: Random Forest Training ===
rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
rf.fit(X_train_bal, y_train_bal)

# === STEP 11: Evaluation ===
y_pred = rf.predict(X_test)
y_pred_proba = rf.predict_proba(X_test)[:, 1]
cm = confusion_matrix(y_test, y_pred)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_pred_proba)

print(f'Accuracy: {accuracy:.4f}')
print(f'Precision: {precision:.4f}')
print(f'Recall: {recall:.4f}')
print(f'F1-Score: {f1:.4f}')
print(f'AUC-ROC: {auc:.4f}')
print('\nConfusion Matrix:')
print(cm)
print('\nClassification Report:')
print(classification_report(y_test, y_pred, target_names=['Normal','Attack']))

# === STEP 12: Save Everything Needed for Scapy ===

# 1. Save the Model
joblib.dump(rf, 'random_forest_model.pkl')

# 2. Save the Scaler (Crucial for numerical features)
joblib.dump(scaler, 'scaler.pkl')

# 3. Save the Feature Names (So Scapy knows the order: port, then bytes, then proto...)
# Note: We need the columns of X *after* dropping the high-cardinality strings
feature_names = X.columns.tolist() 
joblib.dump(feature_names, 'feature_names.pkl')

# 4. Save the Label Encoders (Crucial for converting 'tcp' -> 1)
# We need to re-create the dictionary of encoders used in Step 3
encoders = {}
for col in df.columns:
    if col in feature_names and col not in ['label', 'type']:
        # We need to verify if this column was actually encoded
        # In your original script, you overwrote the df, so the original encoders are lost.
        # FIX: You typically need to store 'le' in a dict inside the Step 3 loop.
        pass 

print("Model and metadata saved!")

# === Confusion Matrix Plot ===
plt.figure(figsize=(4,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal','Attack'], yticklabels=['Normal','Attack'])
plt.xlabel('Predicted')
plt.ylabel('True')
plt.title('Confusion Matrix')
plt.show()

# === ROC Curve ===
fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
plt.figure(figsize=(6,4))
plt.plot(fpr, tpr, label=f'AUC = {auc:.4f}')
plt.plot([0,1],[0,1],'k--',label='Random')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend()
plt.show()
