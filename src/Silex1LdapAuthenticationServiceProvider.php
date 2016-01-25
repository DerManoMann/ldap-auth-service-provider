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

use Silex\Application;
use Silex\ServiceProviderInterface;
use Zend\Ldap\Ldap;
use Radebatz\Silex\LdapAuth\Security\Core\Authentication\Provider\LdapAuthenticationProvider;
use Radebatz\Silex\LdapAuth\Security\Core\User\LdapUserProvider;

/**
 * Ldap authentication service provider.
 */
class Silex1LdapAuthenticationServiceProvider implements ServiceProviderInterface
{
    protected $serviceName;

    /**
     * Create new instance.
     *
     * @param string $serviceName Service name.
     */
    public function __construct($serviceName = 'ldap')
    {
        $this->serviceName = $serviceName;
    }

    /**
     * {@inheritDoc}
     */
    public function register(Application $app)
    {
        // our name
        $serviceName = $this->serviceName;

        $defaults = array(
            // authentication defaults
            'auth' => array(
                // default is custom
                'entryPoint' => null,
                // default roles for all authenticated users:
                // we do need at least one to make UsernamePasswordToken flag authenticated if we use the provider stand alone
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
        );

        $app['security.ldap.config'] = $app->protect(function ($serviceName) use ($app, $defaults) {
            $options = isset($app['security.ldap.'.$serviceName.'.options']) ? $app['security.ldap.'.$serviceName.'.options'] : array();
            // replace within each key
            foreach (array_keys($defaults) as $key) {
                $options[$key] = array_replace($defaults[$key], array_key_exists($key, $options) ? $options[$key] : array());
            }

            return $options;
        });

        // the actual Ldap resource
        if (!isset($app['security.ldap.'.$serviceName.'.ldap'])) {
            $app['security.ldap.'.$serviceName.'.ldap'] = function () use ($app, $serviceName) {
                // we need just the ldap options here
                return new Ldap($app['security.ldap.config']($serviceName)['ldap']);
            };
        }

        // ready made user provider
        if (!isset($app['security.ldap.'.$serviceName.'.user_provider'])) {
            $app['security.ldap.'.$serviceName.'.user_provider'] = $app->protect(function ($options = array()) use ($app, $serviceName) {
                return new LdapUserProvider($serviceName, $app['security.ldap.'.$serviceName.'.ldap'], $app['logger'], $options);
            });
        }

        // set up authentication provider factory and user provider
        $app['security.authentication_listener.factory.'.$serviceName] = $app->protect(function ($name, $options) use ($app, $serviceName) {
            $serviceOptions = $app['security.ldap.config']($serviceName);
            $entryPoint = $serviceOptions['auth']['entryPoint'];

            if ($entryPoint && !isset($app['security.entry_point.'.$name.'.'.$entryPoint])) {
                $app['security.entry_point.'.$name.'.'.$entryPoint] = $app['security.entry_point.'.$entryPoint.'._proto']($name, $options);
            }

            // define the authentication provider object
            $app['security.authentication_provider.'.$name.'.'.$serviceName] = function () use ($app, $name, $serviceOptions, $serviceName) {
                return new LdapAuthenticationProvider(
                    $serviceName,
                    $app['security.user_provider.'.$name],
                    $app['security.ldap.'.$serviceName.'.ldap'],
                    $app['logger'],
                    $serviceOptions['auth']
                );
            };

            // define the authentication listener object
            if ($entryPoint) {
                $app['security.authentication_listener.'.$name.'.'.$serviceName] = $app['security.authentication_listener.'.$entryPoint.'._proto']($name, $options);
            }

            return array(
                // the authentication provider id
                'security.authentication_provider.'.$name.'.'.$serviceName,
                // the authentication listener id
                'security.authentication_listener.'.$name.'.'.$serviceName,
                // the entry point id
                $entryPoint ? 'security.entry_point.'.$name.'.'.$entryPoint : null,
                // the position of the listener in the stack
                'pre_auth',
            );
        });
    }

    /**
     * {@inheritDoc}
     */
    public function boot(Application $app)
    {
    }
}
