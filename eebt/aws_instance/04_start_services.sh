#!/bin/bash
# Enable sql and freeradius

service freeradius stop
service freeradius start
nohup sockd | usage_ctrl >>/dev/null 2>&1 &
