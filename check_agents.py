import json, sys
with open('/opt/antivirus-server/agents.json') as f:
    d = json.load(f)
print('Agents:', list(d.keys()))
for did, a in d.items():
    conns = a.get('network_connections', [])
    print(f'\n{did}: {len(conns)} connections')
    for c in conns[:15]:
        proc = c.get('process', '?')
        rip = c.get('remote_ip', '')
        rport = c.get('remote_port', 0)
        status = c.get('status', '')
        print(f'  {proc} -> {rip}:{rport} [{status}]')
