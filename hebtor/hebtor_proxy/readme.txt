

###### Initialize ###################

# install dependencies, this will install tor, python3 and relative modules, and microsocks, a tiny socks5 server for our demo

# sudo ./00_install_dependencies.sh

# init configs

python3 ctrl.py --init

# then edit broker hidden address in ~/.hebtor/config.json
python3 ctrl.py --start-tor
python3 ctrl.py --get-broker-key




# init database

python3 manage.py makemigrations
python3 manage.py migrate


#

##### Daily running ##################

python3 ctrl.py --start-tor

# start hCaptcha payment site

python3 manage.py runserver

# advertise

python3 ctrl.py --advertise

# offline

python3 ctrl.py --offline



# todo

modify microsocks, add timeout, bytes out action, allow multiple credentials/users
