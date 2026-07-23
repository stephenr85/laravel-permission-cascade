<?php

namespace Rushing\PermissionCascade\Support;

use Rushing\PermissionCascade\Contracts\CredentialScopeResolver;

/**
 * The default, unbound resolver: always unscoped. When nothing narrows the acting
 * credential, authorization is byte-for-byte the principal's — today's behaviour.
 */
class NullCredentialScopeResolver implements CredentialScopeResolver
{
    public function resolve(): ?array
    {
        return null;
    }
}
