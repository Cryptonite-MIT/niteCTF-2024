#!/bin/bash

./stop.sh

python3 serverB.py &
python3 serverC.py &
python3 oauth.py
