import requests, json
TOKEN = 'gd_pat_nPtsrrr2zjljEbheV6vk5hXNGoNc8tvCQq5D2Ug0pTJ_56cfa605'
headers = {'Authorization': f'Bearer {TOKEN}'}
r = requests.get('https://api.godaddy.com/v1/domains/soluzka.com/records', headers=headers, timeout=10)
print('Status:', r.status_code)
records = json.loads(r.text)
for rec in records:
    print(f"{rec['type']:6} {rec['name']:20} -> {rec['data']}")
