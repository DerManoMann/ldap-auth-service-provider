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

use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class CustomUserProvider implements UserProviderInterface
{
    public function loadUserByUsername($username)
    {
        return new User($username, null, array('ROLE_USER'));
    }

    public function refreshUser(UserInterface $user)
    {
    }

    public function supportsClass($class)
    {
    }

}
