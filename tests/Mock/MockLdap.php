<?php

/*
 * This file is part of the LdapAuthentication service provider.
 *
 * (c) Martin Rademacher <mano@radebatz.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Radebatz\Silex\LdapAuth\Tests\Mock;

use Zend\Ldap\Ldap;
use Zend\Ldap\Exception\LdapException;

/**
 * Mock ldap class.
 */
class MockLdap extends Ldap
{
    protected $users;

    public function __construct(array $users = array())
    {
        $this->users = $users;
    }

    public function bind($username = null, $password = null)
    {
        foreach ($this->users as $user) {
            if ($user['username'] == $username && $user['password'] == $password) {
                return $this;
            }
        }

        throw new LdapException();
    }

    public function search($filter, $basedn = null, $scope = self::SEARCH_SCOPE_SUB, array $attributes = array(),
                           $sort = null, $collectionClass = null, $sizelimit = 0, $timelimit = 0
    ) {
        $data = array();
        foreach ($this->users as $user) {
            // using '%s' as filter...
            if ($user['username'] == $filter) {
                $data[] = array(
                    'samaccountname' => array($filter),
                    'dn' => $filter,
                    'givenname' => array($user['firstName']),
                    'memberof' => $user['groups'],
                );
            }
        }

        return $this->createCollection(new MockDefaultIterator($data), $collectionClass);
    }
}
