<?php

use Rushing\PermissionCascade\Tests\Fixtures\AccessGrant;
use Rushing\PermissionCascade\Tests\Fixtures\Seal;
use Rushing\PermissionCascade\Tests\Fixtures\SealPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\Stamp;
use Rushing\PermissionCascade\Tests\Fixtures\StampPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;
use Rushing\PermissionCascade\Tests\Fixtures\VaultPolicy;

/**
 * Fleet ADR 0006 C2 on the LIST plane (credential-scope 05): `BaseModelPolicy::scopeForUser()` narrows under a scoped
 * credential exactly as the per-record rungs do. The morph owner's inherent rows need `{model}.view` or
 * `{model}.own.view` on the token; the tier and grant rows need `{model}.view` or `{model}.shared.view`. A token that
 * names none of them lists nothing. The principal half still applies: a carried name never widens what the user's own
 * row scope would list. Unscoped calls and guests are unchanged (VisibilityScopeForUserTest, MorphOwnerTest).
 */
beforeEach(function () {
    actingTeam(1);
    $this->user = User::create(['name' => 'Actor', 'email' => 'actor@example.test']);
    $this->other = User::create(['name' => 'Other', 'email' => 'other@example.test']);
    $this->actingAs($this->user);
});

function rowIds($policy, $query, $user): array
{
    return $policy->scopeForUser($query, $user)->pluck('id')->sort()->values()->all();
}

it('lists the tier and grant rows to a scoped token only when it carries the shared or the action name', function () {
    $tenant = Vault::create(['name' => 'tenant', 'user_id' => $this->other->id, 'visibility' => 'tenant']);
    $granted = Vault::create(['name' => 'granted', 'user_id' => $this->other->id, 'visibility' => 'private']);
    Vault::create(['name' => 'private', 'user_id' => $this->other->id, 'visibility' => 'private']);
    AccessGrant::create([
        'grantable_type' => $granted->getMorphClass(), 'grantable_id' => $granted->id,
        'grantee_type' => $this->user->getMorphClass(), 'grantee_id' => $this->user->id,
        'ability' => 'view', 'effect' => 'allow',
    ]);
    $shared = collect([$tenant->id, $granted->id])->sort()->values()->all();

    // Unscoped: the tier row and the granted row.
    expect(rowIds(new VaultPolicy, Vault::query(), $this->user))->toBe($shared);

    // A scoped token naming something else lists nothing; the shared rung's name or the action's admits the branch.
    bindScope(['widgets.export']);
    expect(rowIds(new VaultPolicy, Vault::query(), $this->user))->toBe([]);
    bindScope(['vault.shared.view']);
    expect(rowIds(new VaultPolicy, Vault::query(), $this->user))->toBe($shared);

    // The principal half: `vault.view` on the token does not make a user without it see every row.
    bindScope(['vault.view']);
    expect(rowIds(new VaultPolicy, Vault::query(), $this->user))->toBe($shared);
});

it('lists the morph owner\'s inherent rows to a scoped token only when it carries the own or the action name', function () {
    $mine = Seal::create([
        'name' => 'mine', 'visibility' => 'private',
        'user_type' => $this->user->getMorphClass(), 'user_id' => (string) $this->user->getKey(),
    ]);
    Seal::create([
        'name' => 'theirs', 'visibility' => 'private',
        'user_type' => $this->other->getMorphClass(), 'user_id' => (string) $this->other->getKey(),
    ]);
    $stamp = Stamp::create([
        'name' => 'mine',
        'user_type' => $this->user->getMorphClass(), 'user_id' => (string) $this->user->getKey(),
    ]);

    bindScope(['seal.shared.view', 'widgets.export']);
    expect(rowIds(new SealPolicy, Seal::query(), $this->user))->toBe([])
        ->and(rowIds(new StampPolicy, Stamp::query(), $this->user))->toBe([]);

    bindScope(['seal.own.view', 'stamp.own.view']);
    expect(rowIds(new SealPolicy, Seal::query(), $this->user))->toBe([$mine->id])
        ->and(rowIds(new StampPolicy, Stamp::query(), $this->user))->toBe([$stamp->id]);

    // Still only the user's own row: carrying the name for another user's record is no ownership.
    bindScope(['seal.view']);
    expect(rowIds(new SealPolicy, Seal::query(), $this->user))->toBe([$mine->id]);
});

it('leaves a guest\'s tier rows unchanged while a scope is bound', function () {
    Vault::create(['name' => 'platform', 'user_id' => $this->other->id, 'visibility' => 'platform']);
    Vault::create(['name' => 'private', 'user_id' => $this->other->id, 'visibility' => 'private']);
    $unscoped = rowIds(new VaultPolicy, Vault::query(), null);

    bindScope(['widgets.export']);

    expect(rowIds(new VaultPolicy, Vault::query(), null))->toBe($unscoped);
});
