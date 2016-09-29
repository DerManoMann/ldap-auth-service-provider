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

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Radebatz\Silex\LdapAuth\Security\Core\User\LdapUser;

class CustomUserProvider implements UserProviderInterface
{
    public function loadUserByUsername($username)
    {
        $user = new LdapUser($username, null, array('ROLE_USER'));
        $user->setAuthName($username);

        return $user;
    }

    public function refreshUser(UserInterface $user)
    {
    }

    public function supportsClass($class)
    {
    }
}
