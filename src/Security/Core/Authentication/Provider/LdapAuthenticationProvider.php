<?php

/*
 * This file is part of the LdapAuthentication service provider.
 *
 * (c) Martin Rademacher <mano@radebatz.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Radebatz\Silex\LdapAuth\Security\Core\Authentication\Provider;

use Exception;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

/**
 * Ldap authentication provider.
 */
class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    protected $providerKey;
    protected $userProvider;
    protected $ldap;
    protected $logger;
    protected $options;

    /**
     * Create instance.
     *
     * @param string                $providerKey  The provider key.
     * @param UserProviderInterface $userProvider A user provider.
     * @param Zend\Ldap\Ldap        $ldap         Ldap serivce.
     * @param Psr\Log\LoggerInterface $logger     Optional logger.
     * @param array                 $options      Options.
     */
    public function __construct($providerKey, UserProviderInterface $userProvider, $ldap, LoggerInterface $logger = null, array $options = array())
    {
        $this->providerKey = $providerKey;
        $this->userProvider = $userProvider;
        $this->ldap = $ldap;
        $this->logger = $logger;
        $this->options = array_merge(array('roles' => array()), $options);
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());
        if ($user && $this->ldapAuth($user->getAuthName(), $token->getCredentials())) {
            return new UsernamePasswordToken($user, null, $this->providerKey, array_unique(array_merge($this->options['roles'], $token->getRoles(), $user->getRoles())));
        }

        throw new AuthenticationException('Ldap authentication failed.');
    }

    /**
     * Validate username / credentials using Ldap.
     *
     * @param string $username    The username.
     * @param string $credentials The credentials.
     *
     * @return bool <code>true</code> if the credentials are valid.
     */
    protected function ldapAuth($username, $credentials)
    {
        try {
            $this->ldap->bind($username, $credentials);

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken;
    }
}
