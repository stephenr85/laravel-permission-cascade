<?php

namespace Rushing\PermissionCascade\Support;

use Rushing\PermissionCascade\Contracts\CredentialScopeResolver;

/**
 * Applies the credential-scope intersection to a single permission-name.
 *
 * This is the *narrow-only* rule the cascade owns: a bound resolver can subtract a
 * permission the principal was otherwise granted, but can never grant one the principal
 * lacks (the principal check happens separately, in the policy). Unscoped ⇒ every
 * permission passes, so unbound behaviour is unchanged.
 */
class CredentialScope
{
    public function __construct(private CredentialScopeResolver $resolver) {}

    /**
     * Whether the acting credential's scope permits exercising this permission-name.
     * Unscoped (null) ⇒ always true.
     */
    public function permits(string $permission): bool
    {
        $scope = $this->resolver->resolve();

        return $scope === null || in_array($permission, $scope, true);
    }

    /**
     * Whether a narrowing scope is currently in force (a credential is acting scoped).
     */
    public function isScoped(): bool
    {
        return $this->resolver->resolve() !== null;
    }
}
