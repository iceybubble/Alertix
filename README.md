Alertix 🚀

Real-Time Log Monitoring & Alert Dashboard

Alertix is a real-time log monitoring and alert system designed to help users visualize activities, track productive vs. distractive time, and receive critical alerts. It collects logs, categorizes them by type and severity, and displays insights through interactive Kibana dashboards.

Features

Log Collection: Python server collects logs from multiple sources.

Categorization: Activities are classified into categories such as Work, Study, Entertainment, News, Finance, Shopping, Adult, and Social Media.

Severity Levels:

Low → Work, Education (productive)

Medium → Social Media, Shopping

High → Entertainment, Gaming

Critical → Adult content, suspicious IPs, possible exploits

Visualizations:

Bar charts for severity distribution

Line charts for critical events over time

Data tables for top suspicious IPs

Pie charts for activity categories

Productive vs. distractive time comparison

Real-Time Alerts: Trigger notifications for critical activities.

Tech Stack

Python 3.x – Server and log processing

Elasticsearch – Log storage and querying

Kibana – Interactive dashboards and visualizations

Installation
1️⃣ Clone the repository
git clone https://github.com/iceybubble/Alertix.git
cd Alertix

2️⃣ Install Python dependencies
pip install -r requirements.txt


Make sure you have Python 3.x installed.

3️⃣ Run Elasticsearch & Kibana

Elasticsearch:
Navigate to your Elasticsearch folder:

./bin/elasticsearch   # Linux/macOS
elasticsearch.bat     # Windows


Open: http://localhost:9200

Kibana:
Navigate to your Kibana folder:

./bin/kibana   # Linux/macOS
kibana.bat     # Windows


Open: http://localhost:5601

4️⃣ Run the Python server
python server.py


The server collects logs and pushes them to Elasticsearch.

Usage

Open Kibana at http://localhost:5601

Create an index pattern for your logs (e.g., logs)

Explore your dashboards:

Bar chart → Severity distribution

Line chart → Critical events over time

Data table → Top suspicious IPs

Pie chart → Activity categories

Productive vs. distractive time visualization

Alerts trigger automatically for Critical severity activities.



How It Works

Log Generation: The Python server receives activity logs.

Categorization & Severity: Logs are classified by type and assigned a severity.

Storage: Logs are indexed into Elasticsearch.

Visualization: Kibana visualizes the data through charts and tables.


Contributing

Contributions are welcome!


Fork the repository

Create a new branch (git checkout -b feature-name)

Make your changes

Commit (git commit -m "Add feature")

Push (git push origin feature-name)

Open a Pull Request


License

This project is licensed under the MIT License.
