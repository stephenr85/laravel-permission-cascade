<?php

use Rushing\PermissionCascade\Tests\Fixtures\AccessGrant;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;
use Rushing\PermissionCascade\Tests\Fixtures\VaultItem;
use Rushing\PermissionCascade\Tests\Fixtures\VaultItemPolicy;

/**
 * Ticket 07: BaseModelPolicy::isSteward() widened to climb visibilityAncestors() when the
 * model itself carries no owner trait. VaultItem (no HasUser/HasUserId of its own, only a
 * containing Vault's) stands in for `rushing/audiostud`'s Timeline\Clip.
 */
beforeEach(function () {
    actingTeam(1);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->actor = User::create(['name' => 'Actor', 'email' => 'actor@example.test']);
    $this->policy = new VaultItemPolicy;
});

it('lets the owning ancestor\'s steward manage a child that carries no owner trait itself', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    $item = VaultItem::create(['name' => 'i', 'vault_id' => $vault->id]);

    expect($this->policy->view($this->owner, $item->fresh()))->toBeTrue();
    expect($this->policy->update($this->owner, $item->fresh()))->toBeTrue();
});

it('denies a non-owner of the ancestor on a child with no owner trait itself', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    $item = VaultItem::create(['name' => 'i', 'vault_id' => $vault->id]);

    expect($this->policy->view($this->actor, $item->fresh()))->toBeFalse();
    expect($this->policy->update($this->actor, $item->fresh()))->toBeFalse();
});

it('lets the climbed ancestor steward manage non-deniably too (anti-lockout still holds)', function () {
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);
    $item = VaultItem::create(['name' => 'i', 'vault_id' => $vault->id]);

    AccessGrant::create([
        'grantable_type' => $item->getMorphClass(),
        'grantable_id' => $item->getKey(),
        'grantee_type' => $this->owner->getMorphClass(),
        'grantee_id' => $this->owner->getKey(),
        'ability' => 'manage',
        'effect' => 'deny',
    ]);

    expect($this->policy->update($this->owner, $item->fresh()))->toBeTrue();
});
