import pandas as pd
# Split data: AI Training (80%) + Testing (20%)
from sklearn.model_selection import train_test_split
# create and train machine learning model for binary prediction
from sklearn.linear_model import LogisticRegression
#evaluate the accuracy machine learning model
from sklearn.metrics import accuracy_score, confusion_matrix
# Improve the Accuracy 
from sklearn.ensemble import RandomForestClassifier  

def translator(Label):
    if Label == "bad":
       return 1
    else:
       return 0


# 1. Load Dataset
print("Loading data... ")
df = pd.read_csv('phishing_site_urls.csv')

# 2. check first rows
print("\n--- First 5 Rows ---")
print(df.head())

# 3. Create New data from URL
print("\n--- Extracting Features ---")

# Feature 1: URL Length 
df['url_length'] = df['URL'].apply(lambda x: len(str(x)))

# Feature 2: Number of dots
df['dot_count'] = df['URL'].apply(lambda x: str(x).count('.'))
df['target'] = df['Label'].apply(translator)

# Feature 3: Suspicious words
suspicious_words = ['secure', 'login', 'update', 'banking']
def check_suspicious(url):
    url_lower = str(url).lower()
    return 1 if any(word in url_lower for word in suspicious_words) else 0

df['has_suspicious_words'] = df['URL'].apply(check_suspicious)

# 4. Result
print(df[['URL','url_length', 'dot_count', 'has_suspicious_words', 'Label']].head())
print(df[['Label' , 'target']].head())

# 5. AI Train/Test
# define Questions (x) and "Answers" (y)
X = df[['url_length', 'dot_count', 'has_suspicious_words']] 
y = df['target']

# dataset Splitter
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Training-data dimensions(Rows, Columns):", X_train.shape)
print("Test-data dimensions(Rows, Columns):", X_test.shape)

#6. 
scannerAI = RandomForestClassifier()
scannerAI.fit(X_train, y_train)

# 7.answer X_test question
y_pred = scannerAI.predict(X_test)

print("Overall Model Accuracy:", accuracy_score(y_test, y_pred))

model_errorCount = confusion_matrix(y_test, y_pred)
print("\n--- Confusion Matrix ---")
print(f"Correctly Identified Sites: {model_errorCount[0][0]}")
print(f"Safe Sites Mistaken for Phishing: {model_errorCount[0][1]}")
print(f"Phishing Sites Missed (DANGER): {model_errorCount[1][0]}")
print(f"Phishing Sites Caught: {model_errorCount[1][1]}")
