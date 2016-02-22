<?php

/*
 * This file is part of the LdapAuthentication service provider.
 *
 * (c) Martin Rademacher <mano@radebatz.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Radebatz\Silex\LdapAuth\Tests;

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Silex\Application;
use Silex\Provider\SessionServiceProvider;
use Radebatz\Silex\LdapAuth\LdapAuthenticationServiceProvider;

/**
 * Test Ldap.
 */
class LdapTest extends LdapAuthTestCase
{

    /**
     * @expectedException Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     */
    public function testLdapExceptionSimple()
    {
        $app = new Application();
        $app['debug'] = true;
        $app->register(new SessionServiceProvider());

        $app['logger'] = new Logger('CLI');
        $app['logger']->pushHandler(new StreamHandler('php://stdout', Logger::DEBUG));
        /*
        */

        $serviceName = 'ldap-form';
        $app->register(new LdapAuthenticationServiceProvider($serviceName));

        // try the user provider with invalid Ldap configuration
        $app['security.ldap.'.$serviceName.'.user_provider']()->loadUserByUsername('mano');
    }

    /**
     * @expectedException Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     */
    public function testLdapExceptionHosts()
    {
        $app = new Application();
        $app['debug'] = true;
        $app->register(new SessionServiceProvider());

        $app['logger'] = new Logger('CLI');
        $app['logger']->pushHandler(new StreamHandler('php://stdout', Logger::DEBUG));
        /*
        */

        $serviceName = 'ldap-form';
        $app->register(new LdapAuthenticationServiceProvider($serviceName), array(
            'security.ldap.'.$serviceName.'.options' => array(
                'ldap' => array(
                    'hosts' => array(
                        'host1',
                        'host2',
                    ),
                ),
            ),
        ));

        // try the user provider with invalid Ldap configuration
        $app['security.ldap.'.$serviceName.'.user_provider']()->loadUserByUsername('mano');
    }
}
