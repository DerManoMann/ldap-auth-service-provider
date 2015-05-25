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

use ArrayIterator;
use Zend\Ldap\Collection\DefaultIterator;

/**
 * Mock ldap class.
 */
class MockDefaultIterator extends DefaultIterator
{
    protected $iterator;

    public function __construct(array $data)
    {
        $this->iterator = new ArrayIterator($data);
    }

    public function current()
    {
        return $this->iterator->current();
    }

    public function key()
    {
        return $this->iterator->key();
    }

    public function next()
    {
        $this->iterator->next();
    }

    public function rewind()
    {
        $this->iterator->rewind();
    }

    public function valid()
    {
        return$this->iterator->valid();
    }

    public function count()
    {
        return $this->iterator->count();
    }
}
