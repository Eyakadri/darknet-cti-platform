#!/usr/bin/env python3
"""Quick Elasticsearch health & index check."""
import sys
from elasticsearch import Elasticsearch
from config.config_loader import config

def main():
    hosts = config.ELASTICSEARCH_HOSTS
    index = config.ELASTICSEARCH_INDEX
    print(f"Using hosts: {hosts}")
    print(f"Index: {index}")
    try:
        es = Elasticsearch(hosts=hosts, timeout=10)
        if not es.ping():
            print("PING FAILED: cluster not reachable")
            return 2
        print("Ping OK")
        health = es.cluster.health()
        print(f"Cluster status: {health.get('status')} nodes={health.get('number_of_nodes')} active_shards={health.get('active_shards')}" )
        if es.indices.exists(index=index):
            count = es.count(index=index).get('count')
            print(f"Index '{index}' exists. Doc count: {count}")
        else:
            print(f"Index '{index}' does NOT exist yet.")
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
