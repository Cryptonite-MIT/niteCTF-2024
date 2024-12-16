#!/bin/bash

# set -e

kill $(ss -tulpn | grep :5000 | awk '{print $7}' | cut -d'=' -f2 | cut -d',' -f1)
kill $(ss -tulpn | grep :5001 | awk '{print $7}' | cut -d'=' -f2 | cut -d',' -f1)
kill $(ss -tulpn | grep :5002 | awk '{print $7}' | cut -d'=' -f2 | cut -d',' -f1)
kill $(ss -tulpn | grep :5003 | awk '{print $7}' | cut -d'=' -f2 | cut -d',' -f1)
