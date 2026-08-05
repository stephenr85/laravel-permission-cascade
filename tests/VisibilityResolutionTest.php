<?php

use Rushing\PermissionCascade\Tests\Fixtures\AccessGrant;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;
use Rushing\PermissionCascade\Tests\Fixtures\VaultPolicy;
use Spatie\Permission\Models\Role;

/**
 * The directory-ACL `.shared.` resolution (ticket 14): steward → nearest grant (deny beats
 * allow) → effective tier → deny. The actor holds NO cascade token, so every case falls through
 * to the shared rung — exactly the path a non-owner tenant member hits.
 */
beforeEach(function () {
    actingTeam(1);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->actor = User::create(['name' => 'Actor', 'email' => 'actor@example.test']);
    $this->policy = new VaultPolicy;
});

function grant(Vault $on, $to, string $ability, string $effect): AccessGrant
{
    return AccessGrant::create([
        'grantable_type' => $on->getMorphClass(),
        'grantable_id' => $on->getKey(),
        'grantee_type' => $to->getMorphClass(),
        'grantee_id' => $to->getKey(),
        'ability' => $ability,
        'effect' => $effect,
    ]);
}

it('lets the steward manage inherently, with no token and non-deniably', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    // Even an explicit deny against the steward cannot wall them out (anti-lockout).
    grant($vault, $this->owner, 'manage', 'deny');

    expect($this->policy->update($this->owner, $vault->fresh()))->toBeTrue();
    expect($this->policy->view($this->owner, $vault->fresh()))->toBeTrue();
});

it('denies a non-steward on a private vault with no grant', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);

    expect($this->policy->view($this->actor, $vault))->toBeFalse();
    expect($this->policy->update($this->actor, $vault))->toBeFalse();
});

it('allows a non-steward via a direct allow grant', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    grant($vault, $this->actor, 'manage', 'allow');

    expect($this->policy->update($this->actor, $vault))->toBeTrue();
});

it('treats manage as covering view (manage ⊇ view)', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    grant($vault, $this->actor, 'manage', 'allow');

    expect($this->policy->view($this->actor, $vault))->toBeTrue();
});

it('does not let a view grant satisfy a manage request', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    grant($vault, $this->actor, 'view', 'allow');

    expect($this->policy->view($this->actor, $vault))->toBeTrue();
    expect($this->policy->update($this->actor, $vault))->toBeFalse();
});

it('lets a deny beat an allow at the same level', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    grant($vault, $this->actor, 'manage', 'allow');
    grant($vault, $this->actor, 'view', 'deny');

    // deny(view) covers manage too (can't manage what you can't view).
    expect($this->policy->view($this->actor, $vault))->toBeFalse();
    expect($this->policy->update($this->actor, $vault))->toBeFalse();
});

it('inherits an allow grant from an ancestor when the vault has none', function () {
    $parent = Vault::create(['name' => 'p', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    $child = Vault::create(['name' => 'c', 'user_id' => $this->owner->id, 'parent_id' => $parent->id]);
    grant($parent, $this->actor, 'view', 'allow');

    expect($this->policy->view($this->actor, $child->fresh()))->toBeTrue();
});

it('lets a nearer deny override an inherited allow (nearest-wins)', function () {
    $parent = Vault::create(['name' => 'p', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    $child = Vault::create(['name' => 'c', 'user_id' => $this->owner->id, 'parent_id' => $parent->id]);
    grant($parent, $this->actor, 'view', 'allow');
    grant($child, $this->actor, 'view', 'deny');

    expect($this->policy->view($this->actor, $child->fresh()))->toBeFalse();
});

it('resolves a grant to a role the actor holds', function () {
    $role = Role::findOrCreate('Editors', 'web');
    $role->update(['team_id' => 1]);
    $this->actor->assignRole($role);

    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    grant($vault, $role, 'manage', 'allow');

    expect($this->policy->update($this->actor->fresh(), $vault))->toBeTrue();
});

it('opens view to any member on a platform tier but gates manage on the admin token', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'platform']);

    expect($this->policy->view($this->actor, $vault))->toBeTrue();
    expect($this->policy->update($this->actor, $vault))->toBeFalse();

    grantPermission($this->actor, 'platform.manage');
    expect($this->policy->update($this->actor->fresh(), $vault))->toBeTrue();
});

it('opens view but not manage to any member on a tenant tier', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'tenant']);

    expect($this->policy->view($this->actor, $vault))->toBeTrue();
    expect($this->policy->update($this->actor, $vault))->toBeFalse();
});

it('inherits the effective tier up the chain while NULL', function () {
    $parent = Vault::create(['name' => 'p', 'user_id' => $this->owner->id, 'visibility' => 'tenant']);
    $child = Vault::create(['name' => 'c', 'user_id' => $this->owner->id, 'parent_id' => $parent->id]);

    // child.visibility is NULL → inherits parent's `tenant` → any member views.
    expect($this->policy->view($this->actor, $child->fresh()))->toBeTrue();
});
