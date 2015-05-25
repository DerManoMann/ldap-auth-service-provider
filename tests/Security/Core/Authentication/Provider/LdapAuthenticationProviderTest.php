<?php

/*
 * This file is part of the LdapAuthentication service provider.
 *
 * (c) Martin Rademacher <mano@radebatz.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Radebatz\Silex\LdapAuth\Tests\Security\Core\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Radebatz\Silex\LdapAuth\Tests\LdapAuthTestCase;
use Radebatz\Silex\LdapAuth\Security\Core\Authentication\Provider\LdapAuthenticationProvider;

/**
 * Test Ldap authentication provider.
 */
class LdapAuthenticationProviderTest extends LdapAuthTestCase
{
    public function testAuthenticate()
    {
        $options = $this->getOptions();

        foreach (array('user', 'admin') as $userKey) {
            $user = $options['test'][$userKey];
            $token = new UsernamePasswordToken($user['username'], $user['password'], 'ldap');
            $this->assertFalse($token->isAuthenticated());
            $provider = new LdapAuthenticationProvider('ldap', new CustomUserProvider(), $this->createLdap(), null, $options['auth']);

            $authenticateToken = $provider->authenticate($token);
            $this->assertNotNull($authenticateToken);
            $this->assertTrue($authenticateToken->isAuthenticated());
        }
    }
}
