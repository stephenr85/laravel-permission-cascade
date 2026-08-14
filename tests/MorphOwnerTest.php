<?php

use Rushing\PermissionCascade\Facades\Ownership;
use Rushing\PermissionCascade\Tests\Fixtures\AccessGrant;
use Rushing\PermissionCascade\Tests\Fixtures\Crest;
use Rushing\PermissionCascade\Tests\Fixtures\Seal;
use Rushing\PermissionCascade\Tests\Fixtures\SealPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\Stamp;
use Rushing\PermissionCascade\Tests\Fixtures\StampPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\User;

/**
 * The HasMorphUser ownership seam: single polymorphic owner via `user_type`/`user_id`
 * columns, taught to every BaseModelPolicy slot the two existing owner traits occupy, with
 * `Ownership::assign()` as the one blessed write path. Stamp = token-gated/legacy path;
 * Seal = directory-ACL (HasVisibility) path; Crest = trait-less columns for the facade.
 */
beforeEach(function () {
    actingTeam(1);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->actor = User::create(['name' => 'Actor', 'email' => 'actor@example.test']);
});

// ── the creating auto-stamp ────────────────────────────────────────────────────────────

it('auto-stamps the authed user on create', function () {
    $this->actingAs($this->owner);

    $stamp = Stamp::create(['name' => 's']);

    expect($stamp->user_type)->toBe($this->owner->getMorphClass())
        ->and((string) $stamp->user_id)->toBe((string) $this->owner->getKey());
});

it('does not stamp when the columns are pre-set', function () {
    $this->actingAs($this->owner);

    $stamp = Stamp::create([
        'name' => 's',
        'user_type' => $this->actor->getMorphClass(),
        'user_id' => (string) $this->actor->getKey(),
    ]);

    expect((string) $stamp->user_id)->toBe((string) $this->actor->getKey());
});

it('does not stamp when no one is authed', function () {
    $stamp = Stamp::create(['name' => 's']);

    expect($stamp->user_type)->toBeNull()->and($stamp->user_id)->toBeNull();
});

// ── the token-gated .own. rung ─────────────────────────────────────────────────────────

it('allows the morph owner through the own rung and denies a non-owner', function () {
    grantPermission($this->owner, 'stamp.own.view');
    grantPermission($this->owner, 'stamp.own.update');
    grantPermission($this->actor, 'stamp.own.view');
    grantPermission($this->actor, 'stamp.own.update');

    $stamp = Stamp::create([
        'name' => 's',
        'user_type' => $this->owner->getMorphClass(),
        'user_id' => (string) $this->owner->getKey(),
    ]);
    $policy = new StampPolicy;

    expect($policy->view($this->owner, $stamp))->toBeTrue()
        ->and($policy->update($this->owner, $stamp))->toBeTrue()
        ->and($policy->view($this->actor, $stamp))->toBeFalse()
        ->and($policy->update($this->actor, $stamp))->toBeFalse();
});

it('lets the morph owner manage with ZERO tokens even without the directory ACL (inherent steward)', function () {
    $stamp = Stamp::create([
        'name' => 's',
        'user_type' => $this->owner->getMorphClass(),
        'user_id' => (string) $this->owner->getKey(),
    ]);
    $policy = new StampPolicy;

    // No permissions granted to anyone: the morph owner still manages their own row (the
    // HasMorphUser contract), a non-owner is denied. Legacy traits stay token-gated here.
    expect($policy->view($this->owner, $stamp))->toBeTrue()
        ->and($policy->update($this->owner, $stamp))->toBeTrue()
        ->and($policy->delete($this->owner, $stamp))->toBeTrue()
        ->and($policy->view($this->actor, $stamp))->toBeFalse()
        ->and($policy->delete($this->actor, $stamp))->toBeFalse();
});

// ── the steward rung (directory ACL) ───────────────────────────────────────────────────

it('lets the morph-pair steward manage with zero tokens and denies a non-owner', function () {
    $seal = Seal::create([
        'name' => 's', 'visibility' => 'private',
        'user_type' => $this->owner->getMorphClass(), 'user_id' => (string) $this->owner->getKey(),
    ]);
    $policy = new SealPolicy;

    expect($policy->view($this->owner, $seal))->toBeTrue()
        ->and($policy->update($this->owner, $seal))->toBeTrue()
        ->and($policy->view($this->actor, $seal))->toBeFalse()
        ->and($policy->update($this->actor, $seal))->toBeFalse();
});

it('keeps the morph-pair steward non-deniable against an explicit deny grant (anti-lockout)', function () {
    $seal = Seal::create([
        'name' => 's', 'visibility' => 'private',
        'user_type' => $this->owner->getMorphClass(), 'user_id' => (string) $this->owner->getKey(),
    ]);

    AccessGrant::create([
        'grantable_type' => $seal->getMorphClass(),
        'grantable_id' => $seal->getKey(),
        'grantee_type' => $this->owner->getMorphClass(),
        'grantee_id' => $this->owner->getKey(),
        'ability' => 'manage',
        'effect' => 'deny',
    ]);

    expect((new SealPolicy)->update($this->owner, $seal->fresh()))->toBeTrue();
});

// ── owner scoping, both query paths ────────────────────────────────────────────────────

it('scopes to morph-owned rows through the legacy path with own.view', function () {
    grantPermission($this->owner, 'stamp.own.view');

    $mine = Stamp::create([
        'name' => 'mine',
        'user_type' => $this->owner->getMorphClass(), 'user_id' => (string) $this->owner->getKey(),
    ]);
    Stamp::create([
        'name' => 'theirs',
        'user_type' => $this->actor->getMorphClass(), 'user_id' => (string) $this->actor->getKey(),
    ]);

    $ids = (new StampPolicy)->scopeForUser(Stamp::query(), $this->owner)->pluck('id')->all();

    expect($ids)->toBe([$mine->id]);
});

it('scopes to morph-owned rows through the directory-ACL own branch with own.view', function () {
    grantPermission($this->owner, 'seal.own.view');

    $mine = Seal::create([
        'name' => 'mine', 'visibility' => 'private',
        'user_type' => $this->owner->getMorphClass(), 'user_id' => (string) $this->owner->getKey(),
    ]);
    Seal::create([
        'name' => 'theirs', 'visibility' => 'private',
        'user_type' => $this->actor->getMorphClass(), 'user_id' => (string) $this->actor->getKey(),
    ]);

    $ids = (new SealPolicy)->scopeForUser(Seal::query(), $this->owner)->pluck('id')->all();

    expect($ids)->toBe([$mine->id]);
});

// ── the blessed write path ─────────────────────────────────────────────────────────────

it('assigns ownership via the facade on a model without the trait', function () {
    $crest = Crest::create(['name' => 'c']);

    Ownership::assign($crest, $this->owner);

    expect($crest->fresh()->user_type)->toBe($this->owner->getMorphClass())
        ->and((string) $crest->fresh()->user_id)->toBe((string) $this->owner->getKey());
});

it('delegates the trait sugar assignUser to the facade and persists', function () {
    $stamp = Stamp::create(['name' => 's']);

    $stamp->assignUser($this->owner);

    expect($stamp->fresh()->user_type)->toBe($this->owner->getMorphClass())
        ->and((string) $stamp->fresh()->user_id)->toBe((string) $this->owner->getKey())
        ->and($stamp->user->is($this->owner))->toBeTrue();
});

it('fills but does not persist an unsaved model via assign', function () {
    $stamp = new Stamp(['name' => 's']);

    Ownership::assign($stamp, $this->owner);

    expect($stamp->exists)->toBeFalse()
        ->and($stamp->user_type)->toBe($this->owner->getMorphClass());

    $stamp->save();

    expect((string) $stamp->fresh()->user_id)->toBe((string) $this->owner->getKey());
});
