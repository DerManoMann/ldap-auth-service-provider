A Silex Ldap authentication service provider
============================================

[![Build Status](https://travis-ci.org/DerManoMann/ldap-auth-service-provider.png)](https://travis-ci.org/DerManoMann/ldap-auth-service-provider)
[![Coverage Status](https://coveralls.io/repos/DerManoMann/ldap-auth-service-provider/badge.png)](https://coveralls.io/r/DerManoMann/ldap-auth-service-provider)

This service provider provides Ldap based authentication and authorization.

## Basic Usage

```php
  // register service with name ldap
  $ldapAuth = 'ldap';
  $app->register(new LdapAuthenticationServiceProvider($ldapAuth));
  
  // configure firewalls
  $app->register(new SecurityServiceProvider(), array(
            'security.firewalls' => array(
                'login' => array(
                    'pattern' => '^/login$',
                ),
                'default' => array(
                    'pattern' => '^.*$',
                    'anonymous' => true,
                    $ldapAuth => array(
                        // form options
                        'check_path' => '/login_check_ldap',
                        'require_previous_session' => false,
                        // auth options
                        'auth' => array(
                            'entryPoint' => 'form',
                        ),
                        // ldap options
                        'ldap' => array(
                            'host' => 'localhost',
                            'username' => 'username-for-initial-bind',
                            'password' => 'xxx',
                        
                        ),
                    ),
                    'users' => function () use ($app, $ldapAuth) {
                        return new LdapUserProvider(
                            $ldapAuth,
                            $app['security.ldap.default.ldap'],
                            $app['logger'],
                            array(
                                'roles' => array(
                                    'CN=Development,OU=Groups,DC=radebatz,DC=net'   => 'ROLE_USER',
                                    'CN=Admins,OU=Groups,DC=radebatz,DC=net'        => 'ROLE_ADMIN',
                                ),
                                'baseDn' => 'DC=radebatz,DC=net',
                            )
                        );
                    },
                ),
            ),
  
```

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


### Configuring Ldap
The Ldap related code depends on [`zend-ldap`](https://github.com/zendframework/zend-ldap), so all configuration options are just passed through.
For more details check the [`zend-ldap docs`](http://framework.zend.com/manual/current/en/index.html#zend-ldap).


### Custom user class
The LdapUserProvider class allows to configure a custom User class to be used. Only restriction is that the custom class has a constructor that is compatible with the default class `Symfony\\Component\\Security\\Core\\User\\User`.


## Requirements
- Silex 2.0
- PHP 5.5


## License

All code is licensed under the MIT license.


[1]: https://github.com/DerManoMann/ldap-auth-service-provider/archive/master.zip
