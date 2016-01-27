<?php

/*
 * This file is part of the LdapAuthentication service provider.
 *
 * (c) Martin Rademacher <mano@radebatz.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Radebatz\Silex\LdapAuth\Security\Core\User;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Ldap user class that supports custom properties via magic methods.
 */
class LdapUser implements UserInterface
{
    protected $username;
    protected $password;
    protected $roles;
    protected $properties;

    public function __construct($username, $password, array $roles = array())
    {
        $this->username = $username;
        $this->password = $password;
        $this->roles = $roles;
        $this->properties = array();
    }

    /**
     * {@inheritDoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * {@inheritDoc}
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * {@inheritDoc}
     */
    public function getSalt()
    {
        return;
    }

    /**
     * {@inheritDoc}
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * {@inheritDoc}
     */
    public function eraseCredentials()
    {
    }

    public function setRoles(array $roles)
    {
        $this->roles = $roles;
    }

    /**
     * Handle get/set property.
     */
    public function __call($method, array $args)
    {
        $prefix = substr($method, 0, 3);
        if ('set' == $prefix && 1 == count($args)) {
            $property = lcfirst(substr($method, 3));
            $this->properties[$property] = $args[0];

            return;
        } elseif ('get' == $prefix) {
            $property = lcfirst(substr($method, 3));

            return array_key_exists($property, $this->properties) ? $this->properties[$property] : null;
        }

        throw new \RuntimeException('Invalid method: '.$method);
    }

}
