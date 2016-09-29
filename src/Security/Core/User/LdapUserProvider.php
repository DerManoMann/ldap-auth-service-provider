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

use Exception;
use Psr\Log\LoggerInterface;
use Zend\Ldap\Ldap;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Ldap user provider.
 */
class LdapUserProvider implements UserProviderInterface
{
    protected $name;
    protected $ldap;
    protected $logger;
    protected $options;

    /**
     * Create new instance.
     *
     * @param string          $name    The service name.
     * @param Ldap            $ldap    Ldap resource to use.
     * @param LoggerInterface $logger  Optional logger.
     * @param array           $options Configuration options.
     */
    public function __construct($name, Ldap $ldap, LoggerInterface $logger = null, array $options = array())
    {
        $this->name = $name;
        $this->ldap = $ldap;
        $this->logger = $logger;
        $defaults = array(
            // LDAP property used as auth name
            'authName' => 'dn',
            'attr' => array(
                // LDAP attribute => user property
                // these require setter support in the user class
            ),
            'roles' => array(
                // role => group
            ),
            'class' => 'Radebatz\\Silex\\LdapAuth\\Security\\Core\\User\\LdapUser',
            'filter' => '(&(objectClass=user)(sAMAccountName=%s))',
            'baseDn' => null,
        );
        // two level merging
        $this->options = $defaults;
        foreach ($options as $key => $value) {
            $this->options[$key] = is_array($value) ? array_merge($this->options[$key], $value) : $value;
        }
    }

    /**
     * {inheritDoc}.
     */
    public function loadUserByUsername($username)
    {
        $userData = null;
        try {
            if ($collection = $this->ldap->search(sprintf($this->options['filter'], $username), $this->options['baseDn'])) {
                $userData = $collection->getFirst();
            }
        } catch (Exception $e) {
            $unfe = new UsernameNotFoundException('Ldap search failed', 0, $e);
            $unfe->setUsername($username);
            throw $unfe;
        }

        if (!$userData) {
            throw new UsernameNotFoundException(sprintf('Unknown user: username=%s', $username));
        }

        // create user
        $userClass = $this->options['class'];
        $roles = array();
        if (array_key_exists('memberof', $userData) && array_key_exists('roles', $this->options)) {
            foreach ($this->options['roles'] as $group => $role) {
                if (in_array($group, $userData['memberof'])) {
                    $roles[] = $role;
                }
            }
        }

        $user = new $userClass($username, null, array_unique($roles));

        // map auth name
        $authNameAttribute = $this->options['authName'];
        if (array_key_exists($authNameAttribute, $userData)) {
            if ($userData[$authNameAttribute]) {
                // use (first) value
                $user->setAuthName(is_array($userData[$authNameAttribute]) ? $userData[$authNameAttribute][0] : $userData[$authNameAttribute]);
            }
        }

        // set custom attributes
        foreach ($this->options['attr'] as $key => $property) {
            if (array_key_exists($key, $userData) && $userData[$key]) {
                // use (first) value
                $method = 'set'.ucwords($property);
                $user->$method(is_array($userData[$key]) ? $userData[$key][0] : $userData[$key]);
            }
        }

        return $user;
    }

    /**
     * {inheritDoc}.
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {inheritDoc}.
     */
    public function supportsClass($class)
    {
        return $class === $this->options['class'];
    }
}
