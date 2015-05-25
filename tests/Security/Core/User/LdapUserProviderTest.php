<?php

/*
 * This file is part of the LdapAuthentication service provider.
 *
 * (c) Martin Rademacher <mano@radebatz.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Radebatz\Silex\LdapAuth\Tests\Security\Core\User;

use Radebatz\Silex\LdapAuth\Tests\LdapAuthTestCase;
use Radebatz\Silex\LdapAuth\Security\Core\User\LdapUserProvider;

/**
 * Test Ldap user provider.
 */
class LdapUserProviderTest extends LdapAuthTestCase
{
    public function testLoadUser()
    {
        $options = $this->getOptions();
        $provider = new LdapUserProvider('test', $this->createLdap(), null, $options['user']);

        foreach (array('user', 'admin') as $userKey) {
            $username = $options['test'][$userKey]['username'];
            $firstName = $options['test'][$userKey]['firstName'];

            $user = $provider->loadUserByUsername($username);
            $this->assertNotNull($user);
            $this->assertEquals($username, $user->getUsername());
            $this->assertEquals($firstName, $user->getFirstName());
            $this->assertEquals($options['test'][$userKey]['roles'], $user->getRoles());
        }
    }

    public function testRefreshUser()
    {
        $options = $this->getOptions();
        $provider = new LdapUserProvider('test', $this->createLdap(), null, $options['user']);

        $user = $provider->loadUserByUsername($options['test']['user']['username']);
        $this->assertNotNull($user);

        $refreshedUser = $provider->refreshUser($user);
        $this->assertNotNull($refreshedUser);
        $this->assertEquals($refreshedUser->getUsername(), $user->getUsername());
    }
}
