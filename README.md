# Django Expiring Token

[![Requirements Status](https://requires.io/github/KlemenS189/django-expiring-token/requirements.svg?branch=master)](https://requires.io/github/KlemenS189/django-expiring-token/requirements/?branch=master)   [![Build Status](https://travis-ci.org/KlemenS189/django-expiring-token.svg?branch=master)](https://travis-ci.org/KlemenS189/django-expiring-token) [![Coverage Status](https://coveralls.io/repos/github/KlemenS189/django-expiring-token/badge.svg?branch=master)](https://coveralls.io/github/KlemenS189/django-expiring-token?branch=master)
[![PyPI pyversions](https://img.shields.io/badge/python-3.4%20%7C%203.5%20%7C%203.6-blue.svg)](https://pypi.python.org/pypi/ansicolortags/)
[![PyPI pyversions](https://img.shields.io/badge/django-2.0.8%2B-blue.svg)](https://pypi.python.org/pypi/ansicolortags/)




## Introduction
Django Expiring Token provides a very lightweight extension to DRF's existing token authentication.
It implements the following functionalities:

1. Tokens expire after the set time.
2. On each authenticated request, the expiration time is updated by the set time in ```settings.py.```

## Quick setup

1. Do NOT add ```restframework.authtoken``` to your ```INSTALLED_APPS```.
2. Add ```drf_expiring_token``` to your ```INSTALLED_APPS``` setting like this:
    ```
    INSTALLED_APPS = [
        ...
        'drf_expiring_token',
    ]
    ```

3. Include the polls URLconf in your project urls.py like this:
    ```
    path('custom-url/', include('drf_expiring_token.urls')),
    ```
4. Add the expiration time in `settings.py`:
    ```
    EXPIRING_TOKEN_DURATION = timedelta(hours=1)
    # Any timedelta setting can be used! If not set, the default value is 1 day
    ```
5. Add the default authentication class in ```REST_FRAMEWORK``` settings in ```settings.py```
    ```
    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            ...
            'drf_expiring_token.authentication.ExpiringTokenAuthentication',
            ...
        ),
    }
    ```
5. Run `python manage.py migrate` to create package migrations

6. Start the development server an you are good to go.

## Tests
This build is tested against Python versions 3.4, 3.5, 3,6 with Django versions 2.0.8+
To run tests
1. Install ```coverage```
    ```
    pip install coverage
    ```
2. Run tests
    ```
    coverage run runtest.py
    ```





