#!/bin/bash

sed -i "s/nite\.com/${DOMAIN}/g" /etc/nginx/nginx.conf

supervisord -n -c /home/user/supervisord.conf
