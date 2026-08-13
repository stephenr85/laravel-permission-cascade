<?php

use Rushing\PermissionCascade\Tests\Fixtures\Ledger;
use Rushing\PermissionCascade\Tests\Fixtures\LedgerPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\LedgerVisibility;
use Rushing\PermissionCascade\Tests\Fixtures\User;

/**
 * The visibility seam: a host may store the reach tier (and `listed`) off-table via a morph
 * model instead of a `visibility` column on the policied model's own table. `ledgers` carries
 * NO such column — every case here proves the cascade works purely off `ledger_visibilities`.
 * Mirrors VisibilityResolutionTest's key scenarios plus GrantModelSeamTest's fail-loudly shape.
 */
beforeEach(function () {
    actingTeam(1);
    config(['permission-cascade.visibility_model' => LedgerVisibility::class]);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->actor = User::create(['name' => 'Actor', 'email' => 'actor@example.test']);
    $this->policy = new LedgerPolicy;
});

function setTier(Ledger $ledger, ?string $tier, ?bool $listed = null): LedgerVisibility
{
    return LedgerVisibility::create([
        'reachable_type' => $ledger->getMorphClass(),
        'reachable_id' => $ledger->getKey(),
        'tier' => $tier,
        'listed' => $listed,
    ]);
}

it('lets the steward manage inherently with no visibility record at all', function () {
    $ledger = Ledger::create(['name' => 'l', 'user_id' => $this->owner->id]);

    expect($this->policy->update($this->owner, $ledger->fresh()))->toBeTrue();
    expect($this->policy->view($this->owner, $ledger->fresh()))->toBeTrue();
});

it('denies a non-steward on a private-tier ledger with no grant', function () {
    $ledger = Ledger::create(['name' => 'l', 'user_id' => $this->owner->id]);
    setTier($ledger, 'private');

    expect($this->policy->view($this->actor, $ledger->fresh()))->toBeFalse();
});

it('opens view but not manage to any member on a tenant-tier ledger', function () {
    $ledger = Ledger::create(['name' => 'l', 'user_id' => $this->owner->id]);
    setTier($ledger, 'tenant');

    expect($this->policy->view($this->actor, $ledger->fresh()))->toBeTrue();
    expect($this->policy->update($this->actor, $ledger->fresh()))->toBeFalse();
});

it('inherits the effective tier up the chain while NULL, off two morph records', function () {
    $parent = Ledger::create(['name' => 'p', 'user_id' => $this->owner->id]);
    setTier($parent, 'tenant');
    $child = Ledger::create(['name' => 'c', 'user_id' => $this->owner->id, 'parent_id' => $parent->id]);
    // Child has no visibility record at all (the off-table equivalent of a NULL column).

    expect($this->policy->view($this->actor, $child->fresh()))->toBeTrue();
});

it('scopes a listing to the reach-listable tiers, sourced entirely from the morph table', function () {
    $tenant = Ledger::create(['name' => 't', 'user_id' => $this->owner->id]);
    setTier($tenant, 'tenant', listed: true);
    $unlistedTenant = Ledger::create(['name' => 'u', 'user_id' => $this->owner->id]);
    setTier($unlistedTenant, 'tenant', listed: false);
    $private = Ledger::create(['name' => 'p', 'user_id' => $this->owner->id]);
    setTier($private, 'private');

    $ids = $this->policy->scopeForUser(Ledger::query(), $this->actor)->pluck('id')->all();

    expect($ids)->toContain($tenant->id)
        ->and($ids)->not->toContain($unlistedTenant->id)
        ->and($ids)->not->toContain($private->id);
});

it('fails loudly if visibilityRecord() is used without a configured visibility model', function () {
    config(['permission-cascade.visibility_model' => null]);
    $ledger = Ledger::create(['name' => 'l', 'user_id' => $this->owner->id]);

    expect(fn () => $ledger->visibilityRecord()->get())->toThrow(LogicException::class);
});
