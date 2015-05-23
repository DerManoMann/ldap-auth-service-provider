A Silex Ldap authentication service provider
============================================

[![Build Status](https://travis-ci.org/DerManoMann/ldap-auth-service-provider.png)](https://travis-ci.org/DerManoMann/ldap-auth-service-provider)
[![Coverage Status](https://coveralls.io/repos/DerManoMann/ldap-auth-service-provider/badge.png)](https://coveralls.io/r/DerManoMann/ldap-auth-service-provider)


This service provider provides Ldap based authentication and authorization.

Requies Silex 2.0.

## Features

TODO


## Installation

The recommended way to install ldap-auth-service-provider is [through
composer](http://getcomposer.org). Just create a `composer.json` file and
run the `php composer.phar install` command to install it:

    {
        "require": {
            "radebatz/ldap-auth-service-provider": "1.0.*@dev"
        }
    }

Alternatively, you can download the [`ldap-auth-service-provider.zip`][1] file and extract it.


## Usage

### Register per firewall
$app->register(new LdapAuthenticationServiceProvider(), $options);


### Configuring Ldap
-> link to zend ldap docs

### Custom user class
-> constructor compatible with sf security User class
TODO


## License

All code is licensed under the MIT license.


[1]: https://github.com/DerManoMann/ldap-auth-service-provider/archive/master.zip
