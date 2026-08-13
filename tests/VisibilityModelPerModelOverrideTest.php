<?php

use Rushing\PermissionCascade\Tests\Fixtures\LedgerVisibility;
use Rushing\PermissionCascade\Tests\Fixtures\LedgerWithOwnVisibilityModel;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;

/**
 * Ticket 07 follow-up, surfaced fixing rushing/audiostud: `permission-cascade.visibility_model`
 * is a single GLOBAL toggle — setting it moves EVERY HasVisibility model in a host onto the
 * off-table seam at once, including a column-based model (e.g. beam-bookmarks' Shelf) with no
 * relationship to the model that actually wants morph storage. The fix is per-model override of
 * `permissionCascadeVisibilityModel()`, independent of the global config either way.
 */
beforeEach(function () {
    actingTeam(1);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
});

it('lets a model override the visibility model while the global config stays null', function () {
    config(['permission-cascade.visibility_model' => null]);

    $item = LedgerWithOwnVisibilityModel::create(['name' => 'l', 'user_id' => $this->owner->id]);
    LedgerVisibility::create([
        'reachable_type' => $item->getMorphClass(),
        'reachable_id' => $item->getKey(),
        'tier' => 'tenant',
    ]);

    expect($item->fresh()->effectiveVisibility())->toBe('tenant');
});

it('lets an overriding model and a plain column-based model coexist when the global config stays null', function () {
    // The recommended, safe pattern: leave `permission-cascade.visibility_model` unset and let
    // ONLY the models that want off-table storage override the method — Vault (no override)
    // keeps reading its own `visibility` column, undisturbed by LedgerWithOwnVisibilityModel's
    // (a different model) morph override sitting right beside it.
    config(['permission-cascade.visibility_model' => null]);

    $item = LedgerWithOwnVisibilityModel::create(['name' => 'l', 'user_id' => $this->owner->id]);
    LedgerVisibility::create([
        'reachable_type' => $item->getMorphClass(),
        'reachable_id' => $item->getKey(),
        'tier' => 'tenant',
    ]);
    $vault = Vault::create(['name' => 'v', 'user_id' => $this->owner->id, 'visibility' => 'platform']);

    expect($item->fresh()->effectiveVisibility())->toBe('tenant')
        ->and($vault->fresh()->effectiveVisibility())->toBe('platform');
});
