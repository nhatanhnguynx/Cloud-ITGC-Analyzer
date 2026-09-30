# ☁️ Cloud ITGC Analyzer
*Just a tiny Python script I wrote to practice scanning Cloud IAM policies for security risks 🌱*
## 🎯 What is this?
As part of my journey into Tech Risk and IT Audit, I built this simple utility to automate the auditing of Cloud Identity and Access Management (IAM) configurations. It statically analyzes JSON-based resource policies to identify critical **IT General Control (ITGC)** failures
## 🔍 Features
- **JSON Parsing:** Reads standard AWS/Azure style IAM configuration files
- **Public Exposure Detection:** Flags resources with wildcard principals (`"Principal": "*"`) that could lead to data leaks (e.g., open S3 buckets)
- **Privilege Creep Detection:** Identifies excessive administrative rights (`"Action": "*"`)
## 🚀 How to Run
Make sure you have Python installed, then simply test it with the mock data:
```bash
python cloud_iam_auditor.py
💡 The Audit Mindset (NhatAnhNguyen's Note)

"You might notice this codebase is pretty short and simple. That's by design. Coming from an Audit perspective, the goal isn't to write a thousand lines of complicated code. In Tech Risk, true value means writing a precise, lightweight script that gets straight to the point: finding critical vulnerabilities in milliseconds"

peace 💗 love ur guys
