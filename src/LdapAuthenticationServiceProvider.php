<?php

/*
 * This file is part of the LdapAuthentication service provider.
 *
 * (c) Martin Rademacher <mano@radebatz.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Radebatz\Silex\LdapAuth;

use InvalidArgumentException;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Zend\Ldap\Ldap;
use Radebatz\Silex\LdapAuth\Security\Core\Authentication\Provider\LdapAuthenticationProvider;
use Radebatz\Silex\LdapAuth\Security\Core\User\LdapUserProvider;

/**
 * Ldap authentication service provider.
 */
class LdapAuthenticationServiceProvider implements ServiceProviderInterface
{
    protected $serviceName;
    protected $entryPoint;

    /**
     * Create new instance.
     *
     * @param string $serviceName Service name.
     * @param string $entryPoint  The authentication entry point.
     */
    public function __construct($serviceName = 'ldap', $entryPoint = 'form')
    {
        $this->serviceName = $serviceName;
        $this->entryPoint = $entryPoint;
    }

    /**
     * {@inheritDoc}
     */
    public function register(Container $app)
    {
        // our name
        $serviceName = $this->serviceName;
        // entry point
        $entryPoint = $this->entryPoint;

        $defaults = array(
            // authentication defaults
            'auth' => array(
                // default roles for all authenticated users;
                // we do need at least one to make UsernamePasswordToken flag authenticated
                'roles' => array(
                    'ROLE_USER',
                ),
            ),
            // Ldap defaults
            'ldap' => array(
                'host' => 'localhost',
                'bindRequiresDn' => false,
                'username' => null,
                'password' => null,
            ),

            // user provider defaults
            'user' => array(
                'attr' => array(
                    // attribute => property
                    // these require setter support in the user class
                    // 'givenname' => 'firstName'
                ),
                'roles' => array(
                    // group => role
                    //'CN=Development,OU=Groups,DC=globalbrain,DC=net' => 'ROLE_DEVELOPER',
                ),
                'class' => 'Symfony\\Component\\Security\\Core\\User\\User',
                'filter' => '(&(objectClass=user)(sAMAccountName=%s))',
                'baseDn' => null,
            ),
        );

        // firewall options
        $app['security.ldap.'.$serviceName.'.options'] = $app->protect(function ($options) use ($defaults) {
            // replace within each key
            foreach (array_keys($defaults) as $key) {
                $options[$key] = array_replace($defaults[$key], array_key_exists($key, $options) ? $options[$key] : array());
            }

            return $options;
        });

        // set up authentication provider factory and user provider
        $app['security.authentication_listener.factory.'.$serviceName] = $app->protect(function ($name, $options) use ($app, $serviceName, $entryPoint) {
            $options = $app['security.ldap.'.$serviceName.'.options']($options);

            // the actual Ldap resource
            if (!isset($app['security.ldap.'.$name.'.ldap'])) {
                $app['security.ldap.'.$name.'.ldap'] = function () use ($options) {
                    return new Ldap($options['ldap']);
                };
            }

            if ($entryPoint && !isset($app['security.entry_point.'.$name.'.'.$entryPoint])) {
                $app['security.entry_point.'.$name.'.'.$entryPoint] = $app['security.entry_point.'.$entryPoint.'._proto']($name, $options);
            }

            // define the authentication provider object
            $app['security.authentication_provider.'.$name.'.'.$serviceName] = function () use ($app, $name, $options, $serviceName) {
                return new LdapAuthenticationProvider(
                    $serviceName,
                    $app['security.user_provider.'.$name],
                    $app['security.ldap.'.$name.'.ldap'],
                    $app['logger'],
                    $options['auth']
                );
            };

            // define the authentication listener object
            $app['security.authentication_listener.'.$name.'.'.$serviceName] = $app['security.authentication_listener.'.$entryPoint.'._proto']($name, $options);

            return array(
                // the authentication provider id
                'security.authentication_provider.'.$name.'.'.$serviceName,
                // the authentication listener id
                'security.authentication_listener.'.$name.'.'.$serviceName,
                // the entry point id
                $entryPoint ? 'security.entry_point.'.$name.'.'.$entryPoint : null,
                // the position of the listener in the stack
                'pre_auth'
            );
        });
    }

}
