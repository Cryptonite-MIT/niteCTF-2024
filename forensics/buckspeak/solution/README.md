# Buckspeak Solution

- The wav file contains a deepsound password that is encoded using the bucking cipher. The notes have to extracted from the wav file and according to the cipher mapping, they need to be mapped to the corresponding letters of the alphabet.
- This audio file and the password from the previous step need to be put into deepsound to extract an mkv file
- Using ```./mkvextract-helper.sh -f screech.mkv -tavsc``` we can extract the subtitles and the custom font used. Then using a script similar to the one given in the solvescript rendered using the custom font which will give the flag

[Solve script](solve.py)
