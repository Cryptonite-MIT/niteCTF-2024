import frida
import time


def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])


device = frida.get_usb_device()
pid = device.spawn(["io.github.spookie"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)
script = session.create_script(open(r"C:\Users\user\Desktop\hook.js").read())
script.on('message', on_message)
script.load()

while True:
    input("Press Enter to change state...")
    script.post({'type': 'changeState'})

script.join()
