<?php

use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;
use Rushing\PermissionCascade\Tests\Fixtures\VaultPolicy;

/**
 * The package ships no grant model — a host registers one via config. This pins the two
 * ends of that seam: with no model configured the grant rung is INERT (steward + reach
 * tier still resolve, no error), and calling grants() without a model fails loudly.
 */
beforeEach(function () {
    actingTeam(1);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->actor = User::create(['name' => 'Actor', 'email' => 'actor@example.test']);
    $this->policy = new VaultPolicy;
});

it('resolves steward and reach tier with the grant rung inert when no grant model is configured', function () {
    config(['permission-cascade.grant_model' => null]);

    $tenant = Vault::create(['name' => 't', 'user_id' => $this->owner->id, 'visibility' => 'tenant']);
    $private = Vault::create(['name' => 'p', 'user_id' => $this->owner->id, 'visibility' => 'private']);

    // Steward is inherent (no grant model needed); tenant tier still widens view to a member;
    // a private record with no grant falls through to deny — all without touching a grant table.
    expect($this->policy->update($this->owner, $private))->toBeTrue()
        ->and($this->policy->view($this->actor, $tenant))->toBeTrue()
        ->and($this->policy->view($this->actor, $private))->toBeFalse();

    // scopeForUser also degrades cleanly (tier-visible set only, no grant joins).
    $ids = $this->policy->scopeForUser(Vault::query(), $this->actor)->pluck('id')->all();
    expect($ids)->toContain($tenant->id)->and($ids)->not->toContain($private->id);
});

it('fails loudly if grants() is used without a configured grant model', function () {
    config(['permission-cascade.grant_model' => null]);
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'private']);

    expect(fn () => $vault->grants()->get())->toThrow(LogicException::class);
});
