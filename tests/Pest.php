<?php

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
