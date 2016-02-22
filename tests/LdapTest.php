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

    public function loggerProvider()
    {
        $logger = new Logger('CLI');
        $logger->pushHandler(new StreamHandler('php://stdout', Logger::DEBUG));

        return [
            'null' => [null],
            'psr' => [$logger],
        ];
    }

    /**
     * @dataProvider loggerProvider
     * @expectedException Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     */
    public function testLdapExceptionSimple($logger)
    {
        $app = new Application();
        $app['debug'] = true;
        $app->register(new SessionServiceProvider());

        $serviceName = 'ldap-form';
        $app->register(new LdapAuthenticationServiceProvider($serviceName, $logger));

        // try the user provider with invalid Ldap configuration
        $app['security.ldap.'.$serviceName.'.user_provider']()->loadUserByUsername('mano');
    }

    /**
     * @dataProvider loggerProvider
     * @expectedException Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     */
    public function testLdapExceptionHosts($logger)
    {
        $app = new Application();
        $app['debug'] = true;
        $app->register(new SessionServiceProvider());

        $serviceName = 'ldap-form';
        $app->register(new LdapAuthenticationServiceProvider($serviceName, $logger), array(
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
