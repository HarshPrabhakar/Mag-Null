🚀 Overview

Mag-Null is an advanced RF (Radio Frequency) signal intelligence system designed to detect, analyze, and classify drone communications in real-time.

It combines DSP (Digital Signal Processing), signal classification, and interactive visualization to monitor RF environments and identify potential aerial threats such as drones operating on different protocols.


🎯 Key Features

📊 Real-time Spectrum Analysis

FFT-based 512-bin spectrum processing

Live signal strength visualization

📡 Multi-Protocol Detection

Identifies different drone communication patterns

Supports frequency hopping detection

🧠 Signal Classification Engine

Feature extraction from RF signals

Protocol classification logic

🚨 RF Silence Watchdog

Detects signal loss patterns

Infers terminal guidance or out-of-range scenarios

🧑‍💻 Interactive PyQt6 Dashboard

Spectrogram visualization

Contact tracking table

Swarm detection UI

Real-time alerts

🔄 Simulation Engine

Synthetic RF spectrum generation

Multi-drone scenario testing


⚙️ Tech Stack

Python

NumPy – FFT & signal processing

PyQt6 – UI dashboard

Matplotlib / PyQtGraph – Visualization

Custom DSP Pipeline

🧠 How It Works

Signal Input

Real or simulated RF data

DSP Processing

FFT conversion → 512-bin spectrum

Noise floor estimation

Peak detection

Feature Extraction

RSSI trends

Frequency hopping behavior

Signal patterns

Classification

Identify protocol type

Track multiple signals (swarm detection)

Monitoring & Alerts

RF silence detection

Threat alerts via UI

▶️ Getting Started
1️⃣ Clone the Repository
git clone https://github.com/HarshPrabhakar/Mag-Null.git
cd Mag-Null
2️⃣ Create Virtual Environment
python -m venv myenv
myenv\Scripts\activate   # Windows
3️⃣ Install Dependencies
pip install numpy scipy matplotlib pyqtgraph PyQt6 pandas scikit-learn
4️⃣ Run the Application
python -m app.main
🖥️ UI Preview

📈 Live Spectrum Graph

🌈 Spectrogram Heatmap

📋 Signal Contact Table

🚨 Alert Panel

🧭 Swarm Visualization

🔬 Future Enhancements

🤖 Machine Learning-based signal classification

🎥 Video-based drone detection integration

🌐 Web dashboard (FastAPI + React)

📡 SDR (Software Defined Radio) hardware integration

🧠 Deep learning on frequency-domain features

📌 Use Cases

Drone detection & monitoring

RF surveillance systems

Defense & security applications

Research in signal intelligence (SIGINT)

⭐ Contribution

Contributions, issues, and feature requests are welcome!
Feel free to fork and improve the system.

📜 License

This project is open-source and available under the MIT License.

💡 Final Note

Mag-Null is not just a project — it’s a full-stack RF intelligence system combining:

Signal Processing + Visualization + Detection Logic + Simulation
