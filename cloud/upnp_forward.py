import upnpclient

d = upnpclient.Device('http://192.168.1.1:35183/rootDesc.xml')
service = None
for s in d.services:
    if 'WANIPConn' in s.service_id:
        service = s
        break

# Try port 443 with empty internal client first to see the conflict
print('Trying to get specific port mapping for 443...')
try:
    m = service.GetSpecificPortMappingEntry(
        NewRemoteHost='',
        NewExternalPort=443,
        NewProtocol='TCP'
    )
    print(f'Existing 443 mapping: {m}')
except Exception as e:
    print(f'No existing 443 mapping found: {e}')

# Try deleting with different params
print('\nTrying forced delete of 443...')
for host in ['', '0.0.0.0', '192.168.1.133']:
    try:
        service.DeletePortMapping(NewRemoteHost=host, NewExternalPort=443, NewProtocol='TCP')
        print(f'Deleted 443 with host={host}')
    except Exception as e:
        print(f'Delete with host={host}: {e}')

# Try adding 443 again
print('\nAdding 443...')
try:
    service.AddPortMapping(
        NewRemoteHost='',
        NewExternalPort=443,
        NewProtocol='TCP',
        NewInternalPort=443,
        NewInternalClient='192.168.1.133',
        NewEnabled='1',
        NewPortMappingDescription='Caddy HTTPS',
        NewLeaseDuration=0
    )
    print('SUCCESS!')
except Exception as e:
    print(f'Failed: {e}')

# If 443 still fails, try 8443 as alternative
print('\nTrying 8443 as fallback...')
try:
    service.AddPortMapping(
        NewRemoteHost='',
        NewExternalPort=8443,
        NewProtocol='TCP',
        NewInternalPort=443,
        NewInternalClient='192.168.1.133',
        NewEnabled='1',
        NewPortMappingDescription='Caddy HTTPS via 8443',
        NewLeaseDuration=0
    )
    print('SUCCESS! Port 8443 -> 443 forwarded')
except Exception as e:
    print(f'8443 also failed: {e}')
