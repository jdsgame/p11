#!/bin/bash

curl -X POST "http://192.168.69.69:5000/deploy" \
    -H "Content-Type: application/json" \
    -H "Authorization: THETOKEN" \
    -d '{
        "image": "nginx",
        "tag": "1.29.5-alpine"
    }'
