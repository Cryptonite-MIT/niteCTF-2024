#!/bin/bash

INTERVAL=${RESET_INTERVAL:-600}

clean_mongodb() {
    echo "Cleaning database"
    mongosh --norc --quiet --eval 'db = db.getSiblingDB("tammys-tantrums"); db.dropDatabase();'
}

restart_app() {
    echo "Restarting application..."
    if pgrep -f "next-server" > /dev/null; then
        pkill -f "next-server"
        pkill -f "npm run start"
    fi
    node initDb.js 2>&1 &
    npm run start &
}

mongod --fork --logpath /data/db/mongodb.log && sleep 5

node initDb.js 2>&1 &
npm run start &

while true; do
    sleep $INTERVAL
    
    clean_mongodb
    
    restart_app
done
