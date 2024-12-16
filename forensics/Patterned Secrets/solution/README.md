# Patterned Secrets Solution

To recover the deleted message stored in the mmssms.db file use adb

```bash
adb shell
adb su
cd /data/data/com.android.providers.telephony/databases/mmssms.db
exit
adb pull /data/data/com.android.providers.telephony/databases/mmssms.db
```

in the mmssms.db youll find the encyrption used is RC2. and more hints.

use db viewer or strings to get the rc2 encrypted message.

```
4a93f34ce772113729148fb98d58be1834b0de0f4c6a1d06
```

# password

The password is stored in the gesture.key file.

```bash
adb shell
su
exit
adb pull /data/system/gesture.key /data/system/gesture.key
```

put the files in sdcard and then pull if unable to pull directly.

use [gesture-crack](https://github.com/Webblitchy/AndroidGestureCrack) to crcak the pattern.

```
 xxd -p gesture.key | cat > hash.txt
 python3 gesturecrack.py -r 323b357b8026f0afa05c15e76abcad9ed4014bd
```

The Lock Pattern code is [0 4 3 7 5 1 2]

use this as key for rc2 encyrption.(you figure this out form the mmssms.db messages)

![](https://github.com/user-attachments/assets/b59b71c8-818c-46f5-9a99-1f058cdbf22f)

you get the flag.
