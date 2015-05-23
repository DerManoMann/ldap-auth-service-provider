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

use Silex\Application;
use Silex\Provider\SessionServiceProvider;
use Silex\Provider\SecurityServiceProvider;
use Symfony\Component\HttpKernel\Client;
use Radebatz\Silex\LdapAuth\LdapAuthenticationServiceProvider;
use Radebatz\Silex\LdapAuth\Security\Core\User\LdapUserProvider;
use Radebatz\Silex\LdapAuth\Tests\Mock\MockLdap;

/**
 * Test Ldap authentication service provider.
 *
 * Inspired by the Silex SecurityServiceProviderTest code.
 */
class LdapAuthenticationServiceProviderTest extends LdapAuthTestCase
{

    public function testLdapFormAuthentication()
    {
        $app = $this->createApplication('form');

        $client = new Client($app);
        $client->request('get', '/');
        $this->assertEquals('ANONYMOUS', $client->getResponse()->getContent());

        $client->request('post', '/login_check_ldap', array('_username' => 'fabien', '_password' => 'bar'));
        $this->assertEquals('Bad credentials.', $app['security.last_error']($client->getRequest()));
        // hack to re-close the session as the previous assertions re-opens it
        $client->getRequest()->getSession()->save();

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


    public function createApplication($authenticationMethod = 'form')
    {
        $app = new Application();
        $app->register(new SessionServiceProvider());

        $app = call_user_func(array($this, 'add'.ucfirst($authenticationMethod).'Authentication'), $app);

        // ********* //
        $this->registerLdapAuthenticationServiceProvider($app);

        $app['session.test'] = true;

        return $app;
    }

    protected function registerLdapAuthenticationServiceProvider($app)
    {
        $app->register(new LdapAuthenticationServiceProvider());

        $app['security.ldap.default.ldap'] = function () {
            return $this->createLdap();
        };
    }

    private function addFormAuthentication($app)
    {
        $app->register(new SecurityServiceProvider(), array(
            'security.firewalls' => array(
                'login' => array(
                    'pattern' => '^/login$',
                ),
                'default' => array(
                    'pattern' => '^.*$',
                    'anonymous' => true,
                    'ldap' => array_merge(
                        array(
                            'check_path' => '/login_check_ldap',
                            'require_previous_session' => false,
                        ),
                        $this->getOptions()
                    ),
                    'logout' => true,
                    'users' => function() use ($app) {
                        $options = $this->getOptions();

                        return new LdapUserProvider('test', $app['security.ldap.default.ldap'], $app['logger'], $options['user']);
                    },
                    /*
                        // password is foo
                        'fabien' => array('ROLE_USER', '5FZ2Z8QIkA7UTZ4BYkoC+GsReLf569mSKDsfods6LYQ8t+a8EW9oaircfMpmaLbPBh4FOBiiFyLfuZmTSUwzZg=='),
                        'admin'  => array('ROLE_ADMIN', '5FZ2Z8QIkA7UTZ4BYkoC+GsReLf569mSKDsfods6LYQ8t+a8EW9oaircfMpmaLbPBh4FOBiiFyLfuZmTSUwzZg=='),
                    ),
                    */
                ),
            ),
            'security.access_rules' => array(
                array('^/admin', 'ROLE_ADMIN'),
            ),
            'security.role_hierarchy' => array(
                'ROLE_ADMIN' => array('ROLE_USER'),
            ),
        ));

        $app->get('/login', function(Request $request) use ($app) {
            $app['session']->start();

            return $app['security.last_error']($request);
        });

        $app->get('/', function() use ($app) {
            $user = $app['security']->getToken()->getUser();

            $content = is_object($user) ? $user->getUsername() : 'ANONYMOUS';

            if ($app['security']->isGranted('IS_AUTHENTICATED_FULLY')) {
                $content .= 'AUTHENTICATED';
            }

            if ($app['security']->isGranted('ROLE_ADMIN')) {
                $content .= 'ADMIN';
            }

            return $content;
        });

        $app->get('/admin', function() use ($app) {
            return 'admin';
        });

        return $app;
    }

}
