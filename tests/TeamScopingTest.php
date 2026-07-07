<?php

use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;
use Rushing\PermissionCascade\Tests\Fixtures\WidgetPolicy;
use Spatie\Permission\PermissionRegistrar;

it('scopes a permission to the team it was granted in', function () {
    $user = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $policy = new WidgetPolicy;
    $widget = Widget::create(['name' => 'a', 'user_id' => $user->id]);

    // Granted within team 1.
    actingTeam(1);
    grantPermission($user, 'widget.update');
    expect($policy->update($user, $widget))->toBeTrue();

    // The same holder, switched to team 2, does not carry the grant.
    actingTeam(2);
    app(PermissionRegistrar::class)->forgetCachedPermissions();
    $user->unsetRelation('permissions')->unsetRelation('roles');
    expect($policy->update($user, $widget))->toBeFalse();
});

it('uses the configured team foreign key', function () {
    expect(config('permission.column_names.team_foreign_key'))->toBe('team_id');
});
