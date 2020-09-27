#!/bin/bash
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py runserver

# edit torrc

tor -f torrc

# register on hcaptcha, get view key

# generate long term key

python3
>>> from ctrl import *
>>> generate_ecc_key()


# register

# advertise

