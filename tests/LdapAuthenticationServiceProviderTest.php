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
use Silex\Provider\SecurityServiceProvider;
use Symfony\Component\HttpKernel\Client;
use Radebatz\Silex\LdapAuth\LdapAuthenticationServiceProvider;
use Radebatz\Silex\LdapAuth\Security\Core\User\LdapUserProvider;

/**
 * Test Ldap authentication service provider.
 *
 * Inspired by the Silex SecurityServiceProviderTest code.
 */
class LdapAuthenticationServiceProviderTest extends LdapAuthTestCase
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
     */
    public function testLdapHttpAuthentication($logger)
    {
        $app = $this->createApplication('http', $logger);

        $client = new Client($app);

        $client->request('get', '/');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Basic realm="Secured"', $client->getResponse()->headers->get('www-authenticate'));

        $client->request('get', '/', array(), array(), array('PHP_AUTH_USER' => 'dennis', 'PHP_AUTH_PW' => 'foo'));
        $this->assertEquals('dennisAUTHENTICATED', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        $this->assertEquals(403, $client->getResponse()->getStatusCode());

        $client->restart();

        $client->request('get', '/');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Basic realm="Secured"', $client->getResponse()->headers->get('www-authenticate'));

        $client->request('get', '/', array(), array(), array('PHP_AUTH_USER' => 'admin', 'PHP_AUTH_PW' => 'foo'));
        $this->assertEquals('adminAUTHENTICATEDADMIN', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        $this->assertEquals('admin', $client->getResponse()->getContent());
    }

    /**
     * @dataProvider loggerProvider
     */
    public function testLdapFormAuthentication($logger)
    {
        $app = $this->createApplication('form', $logger);

        $client = new Client($app);

        $client->request('get', '/');
        $this->assertEquals('ANONYMOUS', $client->getResponse()->getContent());

        $client->request('post', '/login_check_ldap', array('_username' => 'fabien', '_password' => 'bar'));
        //$this->assertContains('Bad credentials', $app['security.last_error']($client->getRequest()));
        // hack to re-close the session as the previous assertions re-opens it
        //$client->getRequest()->getSession()->save();

        $client->request('post', '/login_check_ldap', array('_username' => 'fabien', '_password' => 'foo'));
        $this->assertEquals('', $app['security.last_error']($client->getRequest()));
        $client->getRequest()->getSession()->save();
        $this->assertEquals(302, $client->getResponse()->getStatusCode());
        $this->assertEquals('http://localhost/', $client->getResponse()->getTargetUrl());

        $client->request('get', '/');
        $this->assertEquals('fabienAUTHENTICATED', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        $this->assertEquals(403, $client->getResponse()->getStatusCode());

        $client->request('get', '/logout');
        $this->assertEquals(302, $client->getResponse()->getStatusCode());
        $this->assertEquals('http://localhost/', $client->getResponse()->getTargetUrl());

        $client->request('get', '/');
        $this->assertEquals('ANONYMOUS', $client->getResponse()->getContent());

        $client->request('get', '/admin');
        $this->assertEquals(302, $client->getResponse()->getStatusCode());
        $this->assertEquals('http://localhost/login', $client->getResponse()->getTargetUrl());

        $client->request('post', '/login_check_ldap', array('_username' => 'admin', '_password' => 'foo'));
        $this->assertEquals('', $app['security.last_error']($client->getRequest()));
        $client->getRequest()->getSession()->save();
        $this->assertEquals(302, $client->getResponse()->getStatusCode());
        $this->assertEquals('http://localhost/admin', $client->getResponse()->getTargetUrl());

        $client->request('get', '/');
        $this->assertEquals('adminAUTHENTICATEDADMIN', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        $this->assertEquals('admin', $client->getResponse()->getContent());
    }

    public function createApplication($authenticationMethod, $logger)
    {
        $app = new Application();
        $app['debug'] = true;
        $app->register(new SessionServiceProvider());

        // ********* //
        $serviceName = 'ldap-'.$authenticationMethod;
        $this->registerLdapAuthenticationServiceProvider($app, $authenticationMethod, $serviceName, $logger);
        $app = call_user_func(array($this, 'add'.ucfirst($authenticationMethod ?: 'null').'Authentication'), $app, $serviceName);

        $app['session.test'] = true;

        return $app;
    }

    protected function registerLdapAuthenticationServiceProvider($app, $authenticationMethod, $serviceName, $logger)
    {
        $app->register(new LdapAuthenticationServiceProvider($serviceName, $logger),
            array(
                'security.ldap.'.$serviceName.'.options' => array_merge(
                    $this->getOptions(),
                    array(
                        'auth' => array(
                            'entryPoint' => $authenticationMethod,
                        ),
                    )
                )
            ),
            $app['logger']
        );

        // need this before the firewall is configured
        $app['security.ldap.'.$serviceName.'.ldap'] = function () {
            return $this->createLdap();
        };
    }

    private function addFormAuthentication($app, $serviceName)
    {
        $app->register(new SecurityServiceProvider(), array(
            'security.firewalls' => array(
                'login' => array(
                    'pattern' => '^/login$',
                ),
                'default' => array(
                    'pattern' => '^.*$',
                    'anonymous' => true,
                    // acts like form
                    $serviceName => array(
                        'check_path' => '/login_check_ldap',
                        'require_previous_session' => false,
                    ),
                    'logout' => true,
                    'users' => function () use ($app, $serviceName) {
                        $options = $this->getOptions();

                        return $app['security.ldap.'.$serviceName.'.user_provider']($options['user']);
                    },
                ),
            ),
            'security.access_rules' => array(
                array('^/admin', 'ROLE_ADMIN'),
            ),
            'security.role_hierarchy' => array(
                'ROLE_ADMIN' => array('ROLE_USER'),
            ),
        ));

        $app->get('/login', function (Request $request) use ($app) {
            $app['session']->start();

            return $app['security.last_error']($request);
        });

        $app->get('/', function () use ($app) {
            $user = $app['security.token_storage']->getToken()->getUser();

            $content = is_object($user) ? $user->getUsername() : 'ANONYMOUS';

            if ($app['security.authorization_checker']->isGranted('IS_AUTHENTICATED_FULLY')) {
                $content .= 'AUTHENTICATED';
            }

            if ($app['security.authorization_checker']->isGranted('ROLE_ADMIN')) {
                $content .= 'ADMIN';
            }

            return $content;
        });

        $app->get('/admin', function () use ($app) {
            return 'admin';
        });

        return $app;
    }

    private function addHttpAuthentication($app, $serviceName)
    {
        $app->register(new SecurityServiceProvider(), array(
            'security.firewalls' => array(
                'default' => array(
                    'pattern' => '^.*$',
                    // acts like http
                    $serviceName => true,
                    'users' => function () use ($app, $serviceName) {
                        $options = $this->getOptions();

                        return $app['security.ldap.'.$serviceName.'.user_provider']($options['user']);
                    },
                ),
            ),
            'security.access_rules' => array(
                array('^/admin', 'ROLE_ADMIN'),
            ),
            'security.role_hierarchy' => array(
                'ROLE_ADMIN' => array('ROLE_USER'),
            ),
        ));

        $app->get('/', function () use ($app) {
            $user = $app['security.token_storage']->getToken()->getUser();
            $content = is_object($user) ? $user->getUsername() : 'ANONYMOUS';

            if ($app['security.authorization_checker']->isGranted('IS_AUTHENTICATED_FULLY')) {
                $content .= 'AUTHENTICATED';
            }

            if ($app['security.authorization_checker']->isGranted('ROLE_ADMIN')) {
                $content .= 'ADMIN';
            }

            return $content;
        });

        $app->get('/admin', function () use ($app) {
            return 'admin';
        });

        return $app;
    }
}
