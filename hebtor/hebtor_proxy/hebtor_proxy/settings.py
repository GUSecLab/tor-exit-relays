"""
Django settings for hebtor_proxy project.

Generated by 'django-admin startproject' using Django 2.2.6.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""
import json
import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 't20ka4(x5+5v43hkiekk^x*6wnqy6xvd(w=*lf@ank4)r1b&a*'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ROOT_PATH = os.path.expanduser("~/.hebtor")


# noinspection DuplicatedCode
def load_config():
    try:
        with open(os.path.join(ROOT_PATH, "config.json"), "r") as f:
            conf = json.loads(f.read())

            conf["BROKER_ADVERTISEMENT_URL"] = os.path.join(conf["BROKER_ROOT_URL"],
                                                            "advertise")  # TODO this is *nix only
            conf["BROKER_OFFLINE_URL"] = os.path.join(conf["BROKER_ROOT_URL"], "offline")
            conf["BROKER_KEY_URL"] = os.path.join(conf["BROKER_ROOT_URL"], "pub_key")
            return conf
    except Exception as e:
        print("Config not found, do this first: python3 ctrl.py --init")
        raise


def load_hidden_address():
    try:
        conf = load_config()
        with open(os.path.expanduser(conf["hidden_hostname_path"]), "r") as f:
            return f.read().strip()
    except Exception as e:
        print("hidden address, do this first: python3 ctrl.py --gen-torrc")
        print("then do: python3 ctrl.py --start-tor")


ALLOWED_HOSTS = [load_hidden_address()]

# Application definition

INSTALLED_APPS = [
    'hCaptcha.apps.HcaptchaConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'hebtor_proxy.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'hebtor_proxy.wsgi.application'

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'
