<?php

use Rushing\PermissionCascade\Contracts\CredentialScopeResolver;
use Rushing\PermissionCascade\Contracts\ReachResolver;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\TestCase;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\PermissionRegistrar;

uses(TestCase::class)->in('.');

/**
 * Point spatie's registrar at the given team for the assignments/checks that follow.
 */
function actingTeam(int $teamId): void
{
    app(PermissionRegistrar::class)->setPermissionsTeamId($teamId);
}

/**
 * Ensure a permission exists (spatie swallows checks for unknown permissions), then
 * grant it to the user within the current team scope.
 */
function grantPermission(User $user, string $name): void
{
    Permission::findOrCreate($name, 'web');
    $user->givePermissionTo($name);
    app(PermissionRegistrar::class)->forgetCachedPermissions();
    $user->unsetRelation('permissions')->unsetRelation('roles');
}

/**
 * Bind a reach resolver into the container, modelling a host that adds its own tier
 * vocabulary (e.g. a public-to-anonymous tier). Mirrors config('permission-cascade.reach_resolver').
 */
function bindReach(ReachResolver $resolver): void
{
    app()->instance(ReachResolver::class, $resolver);
}

/**
 * Bind a fake credential-scope resolver into the container. Pass null to model an
 * unscoped credential (the default), or an array of permission-names to model a scoped
 * one. Mirrors what a host's accounts package does when an API token is acting.
 */
function bindScope(?array $names): void
{
    app()->instance(CredentialScopeResolver::class, new class($names) implements CredentialScopeResolver
    {
        public function __construct(private ?array $names) {}

        public function resolve(): ?array
        {
            return $this->names;
        }
    });
}
