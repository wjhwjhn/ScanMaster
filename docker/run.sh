#!/bin/sh
docker run -it --rm -v ./iplist.txt:/scanMaster/iplist.txt -v ./ports.txt:/scanMaster/ports.txt -v ./release:/scanMaster/release --name scanmaster scanmaster
