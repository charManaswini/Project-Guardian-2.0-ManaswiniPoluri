Detector is built as part of Project Guardian 2.0 to solve a real issue: personal data leaking through API logs and unmonitored endpoints.

The goal is simple, scan incoming data, detect if it contains PII (Personally Identifiable Information), mask it safely, and produce a clean version that can be stored or passed downstream.

The detector works on JSON data stored in CSV rows. Each row is scanned, any sensitive values are redacted, and the output file contains a flag showing if PII was found.(is_pii - True/False)

How does it work basically is; It uses regular expressions to catch structured PII (phone, Aadhaar, passport, UPI, emails, IPs), and uses spaCy Named Entity Recognition for names, addresses, and locations. Marks each row as True or False depending on whether PII was detected. Redacts detected values with masking (e.g., 98XXXXXX10 for phones, j***@gmail.com for emails).

The output is a new CSV file with three columns: record_id, redacted_data_json, is_pii

Install Dependencies as per requirements.txt, And download en_core_web_sm

By Running the Detector by using:
python detector_PoluriManaswini.py iscp_pii_dataset_-_Sheet1.csv
It will create the redacted_output_PoluriManaswini.csv

I had used Manually Labeled Data Given By CTF, and I used it for cross examination of results, achieveing F1 Score to be ~ 0.91
