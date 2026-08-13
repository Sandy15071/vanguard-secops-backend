# Phishing URL Detector

A Python machine-learning project for detecting phishing URLs using
handcrafted lexical and structural URL features and a Random Forest
classifier.

## Current status

**Snapshot:** 2026-08-13

Latest known external evaluation:

  Evaluation                                 Result
  ------------------------- -----------------------
  Benign URLs                  37/37 correct (100%)
  Phishing URLs               99/100 detected (99%)
  Remaining phishing miss                         1

The remaining known miss is:

``` text
journalnoticesgoiases.nl/vocesorte/cadastro.php
```

with a reported phishing probability of **38.5%**.

A previously missed phishing URL:

``` text
www.mega-strana.com/tmp/ro/set/Paypal_Virefication/
```

was later detected at **96.0% phishing** after improving path-word
handling.

> These results are from a small external test set and should not be
> interpreted as production-grade real-world accuracy.

------------------------------------------------------------------------

## Architecture

``` text
Raw URL dataset
      │
      ▼
Feature extraction
(src/feature_extractor.py)
      │
      ▼
data/processed_features.csv
      │
      ▼
Random Forest training
      │
      ▼
model/phishing_model.pkl
      │
      ├──────────────► evaluate_benign.py
      │
      └──────────────► evaluate_phishing.py
```

------------------------------------------------------------------------

## Dataset

Current processed dataset:

``` text
data/processed_features.csv
```

Known shape:

``` text
95,949 rows × 29 columns
```

Labels:

``` text
0 = Legitimate     48,046
1 = Phishing       47,903
```

The dataset is almost perfectly balanced.

The 28 input features are:

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

`label` is the target.

------------------------------------------------------------------------

## Feature extraction

The project uses:

-   URL length
-   hostname/path/query lengths
-   dots, hyphens, slashes
-   digit/letter/special-character counts
-   HTTPS usage
-   IP-address detection
-   `@` detection
-   suspicious double-slash detection
-   domain/subdomain structure
-   TLD presence
-   suspicious keywords
-   suspicious path patterns
-   suspicious path words
-   long numeric sequences
-   hexadecimal-like sequences
-   double extensions
-   digit/letter ratios
-   URL entropy

### Suspicious path handling

The project has a dedicated `suspicious_path_word_count` feature.

Examples of suspicious path terms currently considered include:

``` text
login
signin
sign-in
verify
verification
virefication
secure
account
update
confirm
password
credential
billing
payment
paypal
bank
```

The misspelled term `virefication` was important for detecting one
previously missed phishing URL.

------------------------------------------------------------------------

## Model

Current model:

``` python
RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)
```

Training uses an 80/20 stratified train/test split:

``` python
train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)
```

Model output:

``` text
model/phishing_model.pkl
```

The training script also reports:

-   accuracy
-   precision
-   recall
-   F1 score
-   classification report
-   confusion matrix
-   feature importance

Confusion matrix output:

``` text
model/confusion_matrix.png
```

------------------------------------------------------------------------

## Running the project

Activate the virtual environment first.

Then run the external benign evaluation:

``` powershell
python src/evaluate_benign.py
```

Run the external phishing evaluation:

``` powershell
python src/evaluate_phishing.py
```

The exact training script filename was not captured in the handoff
history, so inspect `src/` before assuming its name.

------------------------------------------------------------------------

## Feature-change workflow

This is important.

If `src/feature_extractor.py` changes, the existing processed CSV must
be regenerated before retraining.

Correct sequence:

``` text
Modify feature extractor
        ↓
Regenerate processed_features.csv
        ↓
Verify columns/values
        ↓
Retrain model
        ↓
Save phishing_model.pkl
        ↓
Run benign evaluation
        ↓
Run phishing evaluation
```

Otherwise the model may be trained without actually seeing the new
feature.

------------------------------------------------------------------------

## Current debugging target

The current remaining missed URL is:

``` text
journalnoticesgoiases.nl/vocesorte/cadastro.php
```

Extracted features:

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

The URL therefore looks fairly ordinary to the current handcrafted
feature set.

The right goal is **not** to hardcode the domain. The goal is to
identify a pattern that also helps detect unseen phishing URLs.

------------------------------------------------------------------------

## Current false-positive warning

The benign test contains these relatively high phishing probabilities:

``` text
https://youtube.com                       48.0%
https://github.com                        36.5%
https://github.com/search?q=python        31.2%
https://github.com/explore                26.6%
https://www.google.com/search?q=cybersecurity 34.0%
```

All were still classified as legitimate under the project's decision
threshold.

This means probability quality/calibration and generalization should be
examined before treating the probability as a trustworthy risk score.

------------------------------------------------------------------------

## Recommended next work

1.  Inspect the actual preprocessing script.
2.  Inspect the exact training script.
3.  Confirm that the current `processed_features.csv` was generated
    after the latest feature changes.
4.  Retrain and record internal validation metrics.
5.  Inspect Random Forest feature importances.
6.  Investigate the remaining
    `journalnoticesgoiases.nl/.../cadastro.php` miss.
7.  Test any proposed feature against both phishing and benign external
    sets.
8.  Add more difficult benign examples and multilingual phishing
    examples.
9.  Avoid URL/domain-specific hardcoded rules.
10. Consider character n-gram or token-based features if handcrafted
    features plateau.

------------------------------------------------------------------------

## Handoff

For the full conversation-derived state and detailed instructions for
another AI, see:

-   `PROJECT_STATE.md`
-   `HANDOFF_PROMPT.txt`
