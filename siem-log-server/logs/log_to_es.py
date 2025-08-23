from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch(
    ["https://localhost:9200"],          # your Elasticsearch URL
    basic_auth=("elastic", "z=56UsyhqhdR1n1eby6h"),  # replace with your ES password
    verify_certs=False                    # only for local dev/self-signed certs
)

def send_log(data):
    try:
        es.index(index="logs", document=data)
        print("Log sent ✅")
    except Exception as e:
        print("Could not send log ⚠️", e)

# Example log
send_log({"user": "katha", "action": "opened GitHub"})
