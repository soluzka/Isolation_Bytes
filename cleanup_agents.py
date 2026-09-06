import json
with open('/opt/antivirus-server/agents.json') as f:
    d = json.load(f)
# Remove stale agents (no connections)
to_remove = [k for k, v in d.items() if not v.get('network_connections')]
for k in to_remove:
    del d[k]
    print(f'Removed stale agent: {k}')
with open('/opt/antivirus-server/agents.json', 'w') as f:
    json.dump(d, f, default=str)
print(f'Remaining agents: {list(d.keys())}')
