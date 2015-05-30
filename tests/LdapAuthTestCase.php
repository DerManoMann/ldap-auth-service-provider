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

use Zend\Ldap\Ldap;
use Symfony\Component\Yaml\Yaml;
use Radebatz\Silex\LdapAuth\Tests\Mock\MockLdap;

/**
 * Ldap auth test case.
 */
abstract class LdapAuthTestCase extends \PHPUnit_Framework_TestCase
{
    protected function getOptions()
    {
        $customOptions = dirname(__DIR__).'/phpunit.local.yml';

        $defaults = array(
            // test data
            'test' => array(
                'mock' => true,
                'user' => array(
                    'username' => 'admin',
                    'firstName' => 'Jim',
                    'password' => 'foo',
                    // expected
                    'roles' => array(
                        'ROLE_USER',
                        'ROLE_ADMIN',
                    ),
                    'groups' => array(
                        'CN=Development,OU=Groups,DC=radebatz,DC=net',
                        'CN=Admins,OU=Groups,DC=radebatz,DC=net',
                    ),
                ),
                'admin' => array(
                    'username' => 'DerManoMann',
                    'firstName' => 'Martin',
                    'password' => 'foo',
                    // expected
                    'roles' => array(
                        'ROLE_USER',
                        'ROLE_ADMIN',
                    ),
                    'groups' => array(
                        'CN=Development,OU=Groups,DC=radebatz,DC=net',
                        'CN=Admins,OU=Groups,DC=radebatz,DC=net',
                    ),
                ),
                'fabien' => array(
                    'username' => 'fabien',
                    'firstName' => 'Fabien',
                    'password' => 'foo',
                    // expected
                    'roles' => array(
                        'ROLE_USER',
                    ),
                    'groups' => array(
                        'CN=Development,OU=Groups,DC=radebatz,DC=net',
                    ),
                ),
                'dennis' => array(
                    'username' => 'dennis',
                    'firstName' => 'Dennis',
                    'password' => 'foo',
                    // expected
                    'roles' => array(
                        'ROLE_USER',
                    ),
                    'groups' => array(
                        'CN=Development,OU=Groups,DC=radebatz,DC=net',
                    ),
                ),
            ),

            'ldap' => array(
            ),
            'auth' => array(
                'roles' => array(
                    'ROLE_USER',
                ),
            ),
            'user' => array(
                'attr' => array(
                    'givenname' => 'firstName',
                ),
                'roles' => array(
                    'CN=Development,OU=Groups,DC=radebatz,DC=net' => 'ROLE_USER',
                    'CN=Admins,OU=Groups,DC=radebatz,DC=net' => 'ROLE_ADMIN',
                ),
                'class' => 'Radebatz\Silex\LdapAuth\Security\Core\User\LdapUser',
                // just the name :)
                'filter' => '%s',
                'baseDn' => 'DC=radebatz,DC=net',
            ),
        );

        $options = file_exists($customOptions) ? Yaml::parse($customOptions) : $defaults;

        return $options;
    }

    protected function createLdap()
    {
        $options = $this->getOptions();
        $mock = $options['test']['mock'];

        return $mock ? new MockLdap($options['test']) : new Ldap($options['ldap']);
    }
}
