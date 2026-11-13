# Windows Security Agent 🛡️

A Python-based Windows Service & Process Monitoring Agent built using the `psutil` library to audit system processes, detect anomalies, and generate security logs.

---

## 📂 Repository Contents

* **`agent.py`**: The core Python script responsible for querying system processes and performing security auditing checks.
* **`README.md`**: Project documentation, architecture overview, and usage instructions.

---

## 🔍 Key Features

* **Process Auditing**: Inspects running system processes in real time.
* **Anomaly Detection**: Flags unusual or unauthorized background activities.
* **Security Logging**: Generates system audit logs for administrative review.
* **Lightweight Utility**: Built entirely using Python and lightweight system libraries.

---

## 🛠️ Libraries Used

* **`psutil`**: For cross-platform retrieval of process information and system utilization metrics.

---

## 💻 How to Run Locally

1. Ensure Python is installed on your Windows system.
2. Install the required dependency via terminal:
   ```bash
   pip install psutil
