A Silex Ldap authentication service provider
============================================
[![Build Status](https://travis-ci.org/DerManoMann/ldap-auth-service-provider.png)](https://travis-ci.org/DerManoMann/ldap-auth-service-provider)
[![Coverage Status](https://coveralls.io/repos/DerManoMann/ldap-auth-service-provider/badge.png)](https://coveralls.io/r/DerManoMann/ldap-auth-service-provider)

This service provider provides Ldap based authentication and authorization.

## Basic Usage
* Form based authentication 
* roles are mapped based on the user being in the specified LDAP group(s).
* The LDAP sn attribute is mapped to the userName property of the user object created

```php
    // register service with name LDAP-FORM
    $app->register(new LdapAuthenticationServiceProvider('LDAP-FORM'), array(
        'security.ldap.LDAP-FORM.options' => array(
            'auth' => array(
                'entryPoint' => 'form',
            ),
            'ldap' => array(
                'host' => 'localhost',
                'username' => 'username-for-initial-bind',
                'password' => 'xxx',
            ),
        )
    ));

    // configure firewalls
    $app->register(new SecurityServiceProvider(), array(
        'security.firewalls' => array(
            'login' => array(
                'pattern' => '^/login$',
            ),
            'default' => array(
                'pattern' => '^.*$',
                'anonymous' => true,
                'LDAP-FORM' => array(
                    // form options
                    'check_path' => '/login_check_ldap',
                    'require_previous_session' => false,
                ),
                'users' => function () use ($app) {
                    // use the pre-configured Ldap user provider
                    return $app['security.ldap.LDAP-FORM.user_provider'](array(
                        // configure LDAP attribute to use for auth bind call (dn is the default)
                        'authName' => 'dn',
                        'attr' => array(
                            // LDAP attribute => user property
                            // these require setter support in the user class
                            'sn' => 'lastName',
                        ),
                        'roles' => array(
                            'CN=Development,OU=Groups,DC=radebatz,DC=net'   => 'ROLE_USER',
                            'CN=Admins,OU=Groups,DC=radebatz,DC=net'        => 'ROLE_ADMIN',
                        ),
                        'baseDn' => 'DC=radebatz,DC=net',
                    ));
                },
            ),
        )
    ));
  
```

## Installation
The recommended way to install ldap-auth-service-provider is [through
composer](http://getcomposer.org).

Install the latest version with:
```
$ composer require radebatz/ldap-auth-service-provider
```

### Configuring Ldap
The Ldap related code depends on [`zend-ldap`](https://github.com/zendframework/zend-ldap), so all configuration options are just passed through.
For more details check the [`zend-ldap docs`](http://framework.zend.com/manual/current/en/index.html#zend-ldap).

The default username value used to autheticate (bind) a user is the LDAP dn attribute (there is a default mapping ````'dn' => 'authName'````). 
To change this or allow an alternative fallback attribute, the following attribute mapping could have been used in the example above:
````
    'attr' => array(
        // LDAP attribute => user property
        'sn' => 'lastName',
    ),
````

NOTE: The property 'authName' of the loaded user object is used for the bind when validating the user credentials (password).
As a default the LDAP 'dn' attribute is mapped to the authName property of the user.

In addition the provider allows to configure a list of hosts to try. If none in the list can't be connected, the regularly configured host is used as
last resort.

Example:
````
ldap:
  ldap:
    hosts:
      - ldap1
      - ldap2
    host: localhost
````
In this case the code will try to connect in the order: ldap1, ldap2, localhost.

### Custom user class
The LdapUserProvider class allows to configure a custom User class to be used.
Only restriction is that the custom class has a constructor that is compatible with the default class `Symfony\\Component\\Security\\Core\\User\\User`.


## Requirements
- Silex 2.0
- PHP 5.5


## License
All code is licensed under the MIT license.


## Changelog
Issues that break backwards compatibility are flagged [BC].

### v1.0.0
* Initial release

### v1.1.0
* Move options into security.ldap.[serviceName] namespace
* Add preconfigured user provider

### v1.2.0
* Add Silex 1.3 support
* bug fixes

### v1.2.1
* Add hosts option to allow a list of fallback servers

### v1.2.2
* Fix LdapException handling
* Add Psr\Log dependency
* [BC] Make the logger an optional second constructor argument instead of taking it from $app

### v1.3.0
* Use users DN as name when trying to bind user  [#15]
  * add new authName mapping to allow to control what LDAP attribute to use to bind when authentication (defaults to DN)
  * Fix merging of LdapUserProvider defaults
  * Check for values array when mapping LDAP data to user instance
  * [BC] Custom user classes *must* either support magic get/set methods or at least implement ````getAuthName()````, ````setAuthName($authName)````
