<?php

use Rushing\PermissionCascade\Models\Grant;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;
use Rushing\PermissionCascade\Tests\Fixtures\VaultPolicy;

/**
 * scopeForUser on a directory-ACL model = own ∪ (tier-visible ∪ direct allow-grants) − direct
 * deny-grants, with the steward's own rows non-deniable. Mirrors the per-record resolution for
 * the listable set 03/04's embeds list is built on.
 */
beforeEach(function () {
    actingTeam(1);
    $this->user = User::create(['name' => 'Actor', 'email' => 'actor@example.test']);
    $this->other = User::create(['name' => 'Other', 'email' => 'other@example.test']);
    $this->policy = new VaultPolicy;
});

function vaultIds($policy, $user): array
{
    return $policy->scopeForUser(Vault::query(), $user)->pluck('id')->all();
}

it('includes the tier-visible set for a member with zero tokens', function () {
    $priv = Vault::create(['name' => 'priv', 'user_id' => $this->other->id, 'visibility' => 'private']);
    $tenant = Vault::create(['name' => 'tenant', 'user_id' => $this->other->id, 'visibility' => 'tenant']);
    $platform = Vault::create(['name' => 'platform', 'user_id' => $this->other->id, 'visibility' => 'platform']);

    $ids = vaultIds($this->policy, $this->user);

    expect($ids)->toContain($tenant->id, $platform->id);
    expect($ids)->not->toContain($priv->id);
});

it('includes own records when the user holds own.view, on top of the tier set', function () {
    grantPermission($this->user, 'vault.own.view');
    $mine = Vault::create(['name' => 'mine', 'user_id' => $this->user->id, 'visibility' => 'private']);
    $theirs = Vault::create(['name' => 'theirs', 'user_id' => $this->other->id, 'visibility' => 'private']);

    $ids = vaultIds($this->policy, $this->user);

    expect($ids)->toContain($mine->id);
    expect($ids)->not->toContain($theirs->id);
});

it('includes records shared by a direct allow grant', function () {
    $shared = Vault::create(['name' => 'shared', 'user_id' => $this->other->id, 'visibility' => 'private']);
    Grant::create([
        'grantable_type' => $shared->getMorphClass(), 'grantable_id' => $shared->id,
        'grantee_type' => $this->user->getMorphClass(), 'grantee_id' => $this->user->id,
        'ability' => 'view', 'effect' => 'allow',
    ]);

    expect(vaultIds($this->policy, $this->user))->toContain($shared->id);
});

it('subtracts a deny grant from the shared set but never from own', function () {
    grantPermission($this->user, 'vault.own.view');
    // Own row with a deny against the user — steward is non-deniable, stays visible.
    $mine = Vault::create(['name' => 'mine', 'user_id' => $this->user->id, 'visibility' => 'tenant']);
    Grant::create([
        'grantable_type' => $mine->getMorphClass(), 'grantable_id' => $mine->id,
        'grantee_type' => $this->user->getMorphClass(), 'grantee_id' => $this->user->id,
        'ability' => 'view', 'effect' => 'deny',
    ]);
    // A tenant-tier row the user would otherwise see, explicitly denied → hidden.
    $denied = Vault::create(['name' => 'denied', 'user_id' => $this->other->id, 'visibility' => 'tenant']);
    Grant::create([
        'grantable_type' => $denied->getMorphClass(), 'grantable_id' => $denied->id,
        'grantee_type' => $this->user->getMorphClass(), 'grantee_id' => $this->user->id,
        'ability' => 'view', 'effect' => 'deny',
    ]);

    $ids = vaultIds($this->policy, $this->user);

    expect($ids)->toContain($mine->id);
    expect($ids)->not->toContain($denied->id);
});

it('returns nothing for a private corpus the user neither owns nor is granted', function () {
    Vault::create(['name' => 'a', 'user_id' => $this->other->id, 'visibility' => 'private']);
    Vault::create(['name' => 'b', 'user_id' => $this->other->id, 'visibility' => 'private']);

    expect(vaultIds($this->policy, $this->user))->toBe([]);
});
