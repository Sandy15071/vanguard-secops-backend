# Phishing Detector --- Project State

**Snapshot date:** 2026-08-13\
**Purpose:** Handoff of the entire known project state from the ChatGPT
conversation to another AI (e.g. Google Gemini).

------------------------------------------------------------------------

## 1. Project overview

This project is a **phishing URL detector** written in Python.

The current approach is:

1.  Take a URL.
2.  Extract handcrafted lexical/structural URL features.
3.  Store those features in a processed CSV dataset.
4.  Train a `RandomForestClassifier`.
5.  Save the trained model as a `.pkl` file with `joblib`.
6.  Evaluate it against external legitimate and phishing URL lists.
7.  Inspect missed examples and add/improve features when useful.

The project is being developed locally on Windows in:

``` text
C:\Users\adriy\OneDrive\Documents\phishing-detector
```

The user runs it inside a Python virtual environment:

``` text
(venv) PS C:\Users\adriy\OneDrive\Documents\phishing-detector>
```

------------------------------------------------------------------------

## 2. Current known project structure

The following paths/files are known from the conversation:

``` text
phishing-detector/
├── data/
│   └── processed_features.csv
├── model/
│   ├── phishing_model.pkl
│   └── confusion_matrix.png
├── src/
│   ├── feature_extractor.py
│   ├── evaluate_benign.py
│   └── evaluate_phishing.py
└── venv/
```

There may be additional files that were not shown in the conversation.
Do not assume the tree above is exhaustive.

------------------------------------------------------------------------

## 3. Current dataset state

The user ran:

``` powershell
python -c "import pandas as pd; df=pd.read_csv('data/processed_features.csv'); print('Columns:'); print(df.columns.tolist()); print('\nShape:', df.shape); print('\nLabel counts:'); print(df['label'].value_counts())"
```

Result:

``` text
Columns:
['url_length', 'hostname_length', 'path_length', 'query_length',
 'num_dots', 'num_hyphens', 'num_slashes', 'num_digits',
 'num_letters', 'num_special_chars', 'uses_https', 'has_ip_address',
 'has_at_symbol', 'has_double_slash', 'domain_length',
 'subdomain_length', 'num_subdomains', 'has_subdomain',
 'has_valid_tld', 'suspicious_word_count',
 'suspicious_path_pattern_count', 'suspicious_path_word_count',
 'has_long_numeric_sequence', 'has_hex_like_sequence',
 'has_double_extension', 'digit_ratio', 'letter_ratio', 'url_entropy',
 'label']

Shape: (95949, 29)

Label counts:
label
0    48046
1    47903
```

Therefore:

-   Rows: **95,949**
-   Columns: **29**
-   Features: **28**
-   Label: **1**
-   Labels are nearly balanced:
    -   Legitimate (`0`): 48,046
    -   Phishing (`1`): 47,903

The important new feature added during debugging is:

``` text
suspicious_path_word_count
```

------------------------------------------------------------------------

## 4. Current feature extractor

The user provided the current `src/feature_extractor.py`.

Imports:

``` python
import re
import math
import ipaddress
import tldextract
from urllib.parse import urlparse
```

Global suspicious words:

``` python
SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "paypal",
    "bank",
    "billing",
    "payment",
    "wallet",
    "auth",
]
```

Suspicious path patterns:

``` python
SUSPICIOUS_PATH_PATTERNS = [
    "/wp-content/",
    "/wp-includes/",
    "/plugins/",
    "/themes/",
    "/cgi-bin/",
    "/upload/",
    "/uploads/",
]
```

Suspicious path words:

``` python
SUSPICIOUS_PATH_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "virefication",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "billing",
    "payment",
    "paypal",
    "bank",
]
```

The extractor contains these helper functions:

-   `has_ip_address(url)`
-   `count_special_characters(url)`
-   `count_digits(url)`
-   `count_letters(url)`
-   `calculate_entropy(text)`
-   `has_long_numeric_sequence(url)`
-   `has_hex_like_sequence(url)`
-   `has_double_extension(url)`
-   `count_suspicious_path_words(path, query)`
-   `suspicious_path_pattern_count(path)`
-   `extract_features(url)`

### Current `count_suspicious_path_words`

The function currently supplied by the user is:

``` python
def count_suspicious_path_words(path, query):
    text = (path + "?" + query).lower()

    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "security",
        "confirm",
        "password",
        "credential",
        "authenticate",
        "payment",
        "wallet",
        "bank",
        "webscr",
        "signin",
        "validate",
    ]

    return sum(text.count(word) for word in suspicious_words)
```

Note: this local list is different from `SUSPICIOUS_PATH_WORDS`. It also
contains a duplicate `"signin"` entry. This has not yet been cleaned up.

### Current `suspicious_path_pattern_count`

The user currently has:

``` python
def suspicious_path_pattern_count(path):
    path_lower = path.lower()

    suspicious_path_word_count = sum(
        1 for word in SUSPICIOUS_PATH_WORDS
        if word in path_lower
    )

    count = 0

    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if pattern in path_lower:
            count += 1

    return count
```

Important: the `suspicious_path_word_count` local variable inside this
function is currently calculated but **not returned or used**. The
actual path-word feature in `extract_features()` comes from
`count_suspicious_path_words(path, query)`.

This distinction should be preserved when debugging rather than assuming
the local variable changes the returned feature.

### Current feature dictionary construction

The user's code DOES have a feature dictionary:

``` python
features = {}
```

It then populates the dictionary.

The relevant lines are:

``` python
features["suspicious_word_count"] = suspicious_word_count

features["suspicious_path_pattern_count"] = suspicious_path_pattern_count(path)

features["suspicious_path_word_count"] = count_suspicious_path_words(path, query)
```

So the current implementation already outputs
`suspicious_path_word_count`.

------------------------------------------------------------------------

## 5. Current feature list

The current 28 feature columns are:

``` text
url_length
hostname_length
path_length
query_length
num_dots
num_hyphens
num_slashes
num_digits
num_letters
num_special_chars
uses_https
has_ip_address
has_at_symbol
has_double_slash
domain_length
subdomain_length
num_subdomains
has_subdomain
has_valid_tld
suspicious_word_count
suspicious_path_pattern_count
suspicious_path_word_count
has_long_numeric_sequence
has_hex_like_sequence
has_double_extension
digit_ratio
letter_ratio
url_entropy
```

`label` is the target and is not an input feature.

------------------------------------------------------------------------

## 6. Debugging history: the missed phishing URL

A key debugging target was:

``` text
www.mega-strana.com/tmp/ro/set/Paypal_Virefication/
```

Initially the feature extraction showed:

``` text
suspicious_word_count: 0
suspicious_path_pattern_count: 0
suspicious_path_word_count: 0
```

The reason was that the path contained:

``` text
Paypal_Virefication
```

and the misspelled phishing keyword is:

``` text
Virefication
```

The `SUSPICIOUS_PATH_WORDS` list was subsequently shown to contain:

``` text
"virefication"
```

The evaluation later showed that this phishing URL was no longer missed
and was classified as:

``` text
PHISHING 96.0% phishing
```

This was a successful improvement.

------------------------------------------------------------------------

## 7. Current second missed phishing URL

The latest phishing evaluation has exactly one missed URL:

``` text
journalnoticesgoiases.nl/vocesorte/cadastro.php
```

Latest result:

``` text
MISSED 38.5% phishing
```

The user extracted its features:

``` text
url_length: 54
hostname_length: 24
path_length: 23
query_length: 0
num_dots: 2
num_hyphens: 0
num_slashes: 4
num_digits: 0
num_letters: 47
num_special_chars: 0
uses_https: 0
has_ip_address: 0
has_at_symbol: 0
has_double_slash: 0
domain_length: 21
subdomain_length: 0
num_subdomains: 0
has_subdomain: 0
has_valid_tld: 1
suspicious_word_count: 0
suspicious_path_pattern_count: 0
suspicious_path_word_count: 0
has_long_numeric_sequence: 0
has_hex_like_sequence: 0
has_double_extension: 0
digit_ratio: 0.0
letter_ratio: 0.8703703703703703
url_entropy: 4.092876280647646
```

This URL currently does not trigger the handcrafted suspicious-word/path
features.

Potentially relevant observations for future work:

-   `cadastro` is a login/registration-related Portuguese word, but
    adding it blindly as a suspicious keyword could create false
    positives.
-   `vocesorte` and `journalnoticesgoiases.nl` are not inherently
    suspicious according to the current feature set.
-   The model gives this URL only 38.5% phishing probability.
-   Do NOT immediately hardcode this one URL or its exact domain as
    phishing. Prefer a generalizable feature or multilingual/semantic
    approach if adding a feature.

------------------------------------------------------------------------

## 8. External legitimate/benign evaluation

The user ran:

``` powershell
python src/evaluate_benign.py
```

The test contained **37 legitimate external URLs**.

Latest reported summary:

``` text
Correct:  37/37
Accuracy: 100.0%
```

Examples of legitimate URLs and predicted phishing probabilities
included:

``` text
https://www.google.com                         0.0%
https://www.google.com/search                  0.5%
https://www.google.com/search?q=cybersecurity 34.0%
https://mail.google.com                       1.5%
https://docs.google.com                       3.0%
https://drive.google.com                     12.0%
https://www.amazon.com                         0.5%
https://www.amazon.com/s?k=laptop              3.5%
https://www.apple.com                           5.5%
https://www.apple.com/iphone                    2.6%
https://www.microsoft.com                      4.5%
https://support.microsoft.com                 15.0%
https://www.wikipedia.org                      5.0%
https://en.wikipedia.org/wiki/Cybersecurity   18.5%
https://github.com                             36.5%
https://github.com/explore                     26.6%
https://github.com/search?q=python             31.2%
https://youtube.com                            48.0%
https://www.youtube.com/results?search_query=python 2.0%
https://www.reddit.com                           1.0%
https://www.linkedin.com                       15.0%
https://www.linkedin.com/jobs                   2.2%
https://www.netflix.com                         2.5%
https://www.adobe.com                            2.5%
https://www.cloudflare.com                    11.0%
https://www.mozilla.org                         3.0%
https://www.python.org                          1.0%
https://www.python.org/downloads                0.0%
https://www.nasa.gov                            9.0%
https://www.ibm.com                              8.5%
https://www.intel.com                            4.0%
https://www.samsung.com                          2.0%
https://www.tesla.com                            5.5%
https://www.paypal.com                            0.0%
https://www.paypal.com/signin                   13.5%
```

Important caveat: **100% accuracy on 37 benign URLs does not prove
real-world benign accuracy**. Several legitimate URLs have moderately
high probabilities, especially GitHub and YouTube:

-   GitHub: 36.5%
-   GitHub Explore: 26.6%
-   GitHub search: 31.2%
-   YouTube root: 48.0%

This should be investigated before claiming the detector is robust.

------------------------------------------------------------------------

## 9. External phishing evaluation

The user ran:

``` powershell
python src/evaluate_phishing.py
```

Latest summary:

``` text
Correctly detected: 99/100
Missed:             1/100
Detection rate:     99.0%
```

The latest missed URL is:

``` text
journalnoticesgoiases.nl/vocesorte/cadastro.php
```

with:

``` text
38.5% phishing
```

A previously missed URL:

``` text
www.mega-strana.com/tmp/ro/set/Paypal_Virefication/
```

was improved to:

``` text
96.0% phishing
```

The external phishing set includes many obviously malicious URLs with
very high scores, often 95--100%.

There are also lower-confidence detections such as:

``` text
www.rallycc.cl/steam/              64.0%
www.7518642n.org/ilhot/Sign In.htm 61.0%
www.farma-gen.com/dosyalar/logon.php 73.0%
www.thegatheringatthecross.com/Robert/webs.htm 81.5%
home.comcast.net/~Jmckenna1/index2.html 73.5%
```

These lower-confidence examples are useful for improving the model.

------------------------------------------------------------------------

## 10. Current training script

The user provided the training code.

Known configuration:

``` python
INPUT_FILE = "data/processed_features.csv"
MODEL_FILE = "model/phishing_model.pkl"
```

It loads the processed CSV:

``` python
df = pd.read_csv(INPUT_FILE)
```

Separates:

``` python
X = df.drop(columns=["label"])
y = df["label"]
```

Uses:

``` python
train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)
```

Random Forest:

``` python
RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)
```

It evaluates:

-   accuracy
-   precision
-   recall
-   F1
-   classification report
-   confusion matrix

It saves:

``` text
model/confusion_matrix.png
```

and:

``` text
model/phishing_model.pkl
```

Feature importances are printed using:

``` python
model.feature_importances_
```

------------------------------------------------------------------------

## 11. Important dataset/model workflow issue

A major part of the conversation was determining whether the
dataset/model needed to be rebuilt after adding a new feature.

Correct workflow:

``` text
Change feature_extractor.py
        ↓
Re-run dataset feature extraction / preprocessing
        ↓
Verify data/processed_features.csv contains the new feature
        ↓
Retrain Random Forest
        ↓
Save model/phishing_model.pkl
        ↓
Run external benign + phishing evaluation
```

The user initially attempted to read:

``` text
data/processed_dataset.csv
```

but that file does not exist.

The actual processed dataset is:

``` text
data/processed_features.csv
```

This is the file used by the training script.

When adding/changing features, the processed dataset must be regenerated
from the original URL dataset before retraining. Otherwise the model
will not actually learn the newly added feature.

------------------------------------------------------------------------

## 12. Current known issue: `suspicious_path_word_count`

There were several debugging questions around where to add:

``` python
path_lower = path.lower()

suspicious_path_word_count = sum(
    1
    for word in SUSPICIOUS_PATH_WORDS
    if word in path_lower
)
```

The important final state is:

-   `extract_features()` creates `features = {}`
-   `extract_features()` already has:

``` python
features["suspicious_path_word_count"] = count_suspicious_path_words(path, query)
```

Therefore the feature is already part of the output.

The separate calculation inside:

``` python
def suspicious_path_pattern_count(path):
```

is redundant and currently unused.

A future cleanup should likely simplify this so there is one clear
implementation for suspicious path word counting.

------------------------------------------------------------------------

## 13. Current model performance snapshot

Latest known external performance:

  Test                                          Result
  ------------------------------------- --------------
  External benign URLs                    37/37 = 100%
  External phishing URLs                  99/100 = 99%
  Total external URLs shown                        137
  Phishing missed                                    1
  Benign false positives in this test                0

However, this is a small manually curated external test set and should
**not** be presented as a statistically validated real-world 99%
detector.

The internal train/test metrics were not included in the latest
conversation output, so their exact values are currently unknown.

------------------------------------------------------------------------

## 14. Recommended immediate next steps

### Step 1 --- Inspect the current training output

Run the training script and save the exact:

-   Accuracy
-   Precision
-   Recall
-   F1
-   Classification report
-   Confusion matrix
-   Feature importances

Do not assume these from the external evaluation.

### Step 2 --- Inspect feature importance

The most important question is whether the newly added:

``` text
suspicious_path_word_count
```

is actually being used by the Random Forest.

### Step 3 --- Investigate the remaining missed URL

Target:

``` text
journalnoticesgoiases.nl/vocesorte/cadastro.php
```

Do not hardcode the exact URL/domain.

Consider whether a general feature can capture registration/login
semantics across languages, such as:

-   multilingual account/login/registration terms
-   common form-action path words
-   suspicious file/path combinations
-   URL tokenization
-   character n-grams
-   domain reputation/age, if the project scope permits external lookup
-   lexical model beyond a fixed English keyword list

### Step 4 --- Investigate false-positive risk

The benign test includes:

``` text
https://youtube.com
```

at:

``` text
48.0% phishing
```

and GitHub URLs around 26.6--36.5%.

The detector should ideally produce much lower scores for common
legitimate sites.

### Step 5 --- Expand evaluation

Create separate validation sets containing:

-   legitimate common sites
-   legitimate login pages
-   legitimate long URLs
-   legitimate URLs with many query parameters
-   legitimate URLs with suspicious-looking words
-   phishing URLs with simple/clean-looking paths
-   multilingual phishing URLs
-   typo-squatting URLs
-   impersonation URLs
-   URL-shortener cases, if supported

### Step 6 --- Consider improving the model

Possible next-stage approaches:

1.  Keep Random Forest and improve handcrafted features.
2.  Add character n-gram TF-IDF features.
3.  Compare Random Forest with Logistic Regression / Linear SVM /
    XGBoost-style models if allowed by the project.
4.  Build a hybrid lexical + character model.
5.  Add a calibrated probability layer if probabilities are intended to
    be shown to users.

Do not make all of these changes at once. Change one component, retrain,
and compare against the same evaluation set.

------------------------------------------------------------------------

## 15. Important project design principle

The project should optimize for **generalization**, not simply getting
100/100 on a fixed external list.

Avoid rules like:

``` python
if "journalnoticesgoiases.nl" in url:
    return phishing
```

or adding exact dataset URLs as special cases.

A feature should represent a pattern likely to occur in unseen phishing
URLs.

------------------------------------------------------------------------

## 16. Commands already used

### Check processed dataset

``` powershell
python -c "import pandas as pd; df=pd.read_csv('data/processed_features.csv'); print('Columns:'); print(df.columns.tolist()); print('\nShape:', df.shape); print('\nLabel counts:'); print(df['label'].value_counts())"
```

### Test a URL's extracted features

``` powershell
python -c "from src.feature_extractor import extract_features; u='journalnoticesgoiases.nl/vocesorte/cadastro.php'; f=extract_features(u); print('\n'.join(f'{k}: {v}' for k,v in f.items()))"
```

### Test the previously missed URL's path features

``` powershell
python -c "from src.feature_extractor import extract_features; u='www.mega-strana.com/tmp/ro/set/Paypal_Virefication/'; f=extract_features(u); print('suspicious_path_word_count:', f['suspicious_path_word_count']); print('suspicious_path_pattern_count:', f['suspicious_path_pattern_count'])"
```

### Run benign external evaluation

``` powershell
python src/evaluate_benign.py
```

### Run phishing external evaluation

``` powershell
python src/evaluate_phishing.py
```

------------------------------------------------------------------------

## 17. Known uncertainty

The conversation does **not** establish:

-   the original raw dataset filename
-   the exact preprocessing script used to create
    `processed_features.csv`
-   the exact training script filename
-   the exact latest internal train/test metric output
-   whether the latest external evaluation model was definitely
    retrained after every feature modification
-   the exact contents of `evaluate_benign.py`
-   the exact contents of `evaluate_phishing.py`
-   the exact original dataset source
-   the exact dependency versions

A handoff AI should ask for these files or inspect the project directory
before making claims about them.

------------------------------------------------------------------------

## 18. Handoff objective

Continue from the current state rather than rebuilding the project from
scratch.

The immediate objective is:

> Improve the remaining phishing miss
> (`journalnoticesgoiases.nl/vocesorte/cadastro.php`) without increasing
> false positives on legitimate URLs, while maintaining a clean
> reproducible feature → dataset → training → evaluation pipeline.

The next AI should first inspect the actual project files if available,
then make the smallest justified change, regenerate
`processed_features.csv`, retrain the model, and rerun both external
evaluation scripts.
