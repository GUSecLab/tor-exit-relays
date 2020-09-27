#!/bin/bash
# Create mysql db

mysql -u root --execute="create database radius;"
mysql -u root --execute='grant all on radius.* to radius@localhost identified by "radpass";'
mysql -u root radius </etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql 
