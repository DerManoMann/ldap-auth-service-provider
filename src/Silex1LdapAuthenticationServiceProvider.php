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

use Psr\Log\LoggerInterface;
use Silex\Application;
use Silex\ServiceProviderInterface;
use Zend\Ldap\Exception\LdapException;
use Zend\Ldap\Ldap;
use Radebatz\Silex\LdapAuth\Security\Core\Authentication\Provider\LdapAuthenticationProvider;
use Radebatz\Silex\LdapAuth\Security\Core\User\LdapUserProvider;

/**
 * Ldap authentication service provider.
 */
class Silex1LdapAuthenticationServiceProvider implements ServiceProviderInterface
{
    protected $serviceName;
    protected $logger;

    /**
     * Create new instance.
     *
     * @param string $serviceName Service name.
     * @param Psr\Log\LoggerInterface $logger     Optional logger.
     */
    public function __construct($serviceName = 'ldap', LoggerInterface $logger = null)
    {
        $this->serviceName = $serviceName;
        $this->logger = $logger;
    }

    /**
     * {@inheritDoc}
     */
    public function register(Application $app)
    {
        // our name
        $serviceName = $this->serviceName;
        // a logger (or not);
        $logger = $this->logger;

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
            $app['security.ldap.'.$serviceName.'.ldap'] = function () use ($app, $serviceName, $logger) {
                // ldap options
                $options = $app['security.ldap.config']($serviceName)['ldap'];

                // check for host list
                if (array_key_exists('hosts', $options) && is_array($options['hosts'])) {
                    // keep local
                    $hosts = $options['hosts'];

                    // remove from options...
                    unset($options['hosts']);

                    foreach ($hosts as $host) {
                        try {
                            // do not override default host
                            $ldap = new Ldap(array_merge($options, ['host' => $host]));

                            // force connect...
                            $ldap->getResource();

                            return $ldap;
                        } catch (LdapException $le) {
                            if ($logger) {
                                $logger->warning(sprintf('LDAP: Failed connecting to host: %s', $host));
                            }
                        }
                    }
                }

                if ($logger) {
                    $logger->info(sprintf('LDAP: Using default host: %s', $options['host']));
                }

                // just pass through all options using configured (single) host
                return new Ldap($options);
            };
        }

        // ready made user provider
        if (!isset($app['security.ldap.'.$serviceName.'.user_provider'])) {
            $app['security.ldap.'.$serviceName.'.user_provider'] = $app->protect(function ($options = array()) use ($app, $serviceName, $logger) {
                return new LdapUserProvider($serviceName, $app['security.ldap.'.$serviceName.'.ldap'], $logger, $options);
            });
        }

        // set up authentication provider factory and user provider
        $app['security.authentication_listener.factory.'.$serviceName] = $app->protect(function ($name, $options) use ($app, $serviceName, $logger) {
            $serviceOptions = $app['security.ldap.config']($serviceName);
            $entryPoint = $serviceOptions['auth']['entryPoint'];

            if ($entryPoint && !isset($app['security.entry_point.'.$name.'.'.$entryPoint])) {
                $app['security.entry_point.'.$name.'.'.$entryPoint] = $app['security.entry_point.'.$entryPoint.'._proto']($name, $options);
            }

            // define the authentication provider object
            $app['security.authentication_provider.'.$name.'.'.$serviceName] = function () use ($app, $name, $serviceOptions, $serviceName, $logger) {
                return new LdapAuthenticationProvider(
                    $serviceName,
                    $app['security.user_provider.'.$name],
                    $app['security.ldap.'.$serviceName.'.ldap'],
                    $logger,
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
