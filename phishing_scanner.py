import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier  

def translator(Label):
    if Label == "bad":
       return 1
    else:
       return 0

# Pull Dataset
print("Loading data... ")
df = pd.read_csv('phishing_site_urls.csv')
print("\n--- First 5 Rows ---") # sanity check
print(df.head())
print("\n--- Extracting Features ---")

# check 1: URL Length 
df['url_length'] = df['URL'].apply(lambda x: len(str(x)))

# check 2: Number of dots
df['dot_count'] = df['URL'].apply(lambda x: str(x).count('.'))
df['target'] = df['Label'].apply(translator)

# check 3: Suspicious words
suspicious_words = ['secure', 'login', 'update', 'banking']
def check_suspicious(url):
    url_lower = str(url).lower()
    for word in suspicious_words:
      if word in url_lower:
        return 1
    return 0

df['has_suspicious_words'] = df['URL'].apply(check_suspicious)

# check 4: Special character counts
df['dash_count'] = df['URL'].apply(lambda x: str(x).count('-'))
df['at_count'] = df['URL'].apply(lambda x: str(x).count('@'))
df['slash_count'] = df['URL'].apply(lambda x: str(x).count('/'))

# check 5: Has IP address

def has_ip_address(url):
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    return 1 if re.search(ip_pattern, str(url)) else 0
df['has_ip'] = df['URL'].apply(has_ip_address)

# check 6: HTTPS check
df['is_https'] = df['URL'].apply(lambda x: 1 if str(x).lower().startswith('https') else 0)

# check 7: Subdomain count
def count_subdomains(url):
    url = str(url).lower().replace('https://', '').replace('http://', '')
    domain_part = url.split('/')[0]
    return domain_part.count('.')
df['subdomain_count'] = df['URL'].apply(count_subdomains)

# check 8: Suspicious TLD
risky_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.club']
def has_risky_tld(url):
    url_lower = str(url).lower()
    for tld in risky_tlds:
      if url_lower.endswith(tld) or tld + '/' in url_lower:
        return 1
    return 0

df['risky_tld'] = df['URL'].apply(has_risky_tld)

# check 9: Digit count in URL
df['digit_count'] = df['URL'].apply(lambda x: sum(c.isdigit() for c in str(x)))

# Result
print(df[['URL','url_length', 'dot_count', 'has_suspicious_words', 'Label']].head())
print(df[['Label' , 'target']].head())

# AI Train/Test
# define Questions (x) and "Answers" (y)
X = df[['url_length', 'dot_count', 'has_suspicious_words', 'dash_count', 'at_count', 'slash_count', 'has_ip', 'is_https', 'subdomain_count', 'risky_tld', 'digit_count']]
y = df['target']

# dataset Splitter
X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=0.2, 
    random_state=42,
    stratify=y
    )

print("Training-data dimensions(Row, Column):", X_train.shape)
print("Test-data dimensions(Rows, Columns):", X_test.shape)

# initiate model
scannerAI = RandomForestClassifier(
    n_estimators=200, 
    class_weight="balanced", 
    min_samples_split=5,
    random_state=42
    )
scannerAI.fit(X_train, y_train)

# answer X_test question
y_pred = scannerAI.predict(X_test)

print("Overall Model Accuracy:", accuracy_score(y_test, y_pred))

model_errorCount = confusion_matrix(y_test, y_pred)
missed_count = model_errorCount[1][0]
if missed_count < 100:
    risk_label = "Good"
elif missed_count < 1000:
    risk_label = "Medium Risk"
else:
    risk_label = "CRITICAL DANGER"

print("\n--- Confusion Matrix ---")
print(f"Safe Sites: {model_errorCount[0][0]}")
print(f"Mistaken: {model_errorCount[0][1]}")
print(f"Missing Sites ({risk_label}): {missed_count}")
print(f"Sites Caught: {model_errorCount[1][1]}")

# what led to current predction results
print("\n--- AI Clue Rankings ---")
for feature, score in zip(X.columns, scannerAI.feature_importances_):
    print(f"{feature}: {score:.4f}")

# user input handling (in the future, we will ignore/check bad input)
test_url = input("Enter Suspicious URL:")
test_data = pd.DataFrame({
'url_length': [len(test_url)],
    'dot_count': [str(test_url).count('.')],
    'has_suspicious_words': [check_suspicious(test_url)],  
    'dash_count' : [str(test_url).count('-')],
    'at_count' : [str(test_url).count('@')],
    'slash_count' : [str(test_url).count('/')],
    'has_ip': [has_ip_address(test_url)],
    'is_https': [1 if test_url.lower().startswith('https') else 0],
    'subdomain_count': [count_subdomains(test_url)],
    'risky_tld': [has_risky_tld(test_url)],
    'digit_count': [sum(c.isdigit() for c in test_url)]

})
prediction = scannerAI.predict(test_data)
if prediction [0] == 1:
    print(" ALERT >> PHISHING URL! ")
else:
    print("SUCCESS: This URL is Safe.")
    
