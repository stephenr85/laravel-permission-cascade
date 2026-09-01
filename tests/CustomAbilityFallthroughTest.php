<?php

use Illuminate\Support\Facades\Gate;
use Rushing\PermissionCascade\Support\CascadePolicyRegistrar;
use Rushing\PermissionCascade\Tests\Fixtures\AttributedFolder;
use Rushing\PermissionCascade\Tests\Fixtures\AttributedNote;
use Rushing\PermissionCascade\Tests\Fixtures\User;

/**
 * The `Gate::define` shadowing regression (permission-cascade ticket 01).
 *
 * Every case here runs with the gate CLOSED: no `Gate::before(fn () => true)`, the actor holds no
 * spatie permission row and is not a Root/superuser, so the only thing that can answer is the
 * resolution order under test.
 */
beforeEach(function () {
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->other = User::create(['name' => 'Other', 'email' => 'other@example.test']);
});

it('lets a hyphenated custom ability reach its Gate::define instead of being shadowed by the policy', function () {
    CascadePolicyRegistrar::register(AttributedFolder::class);

    // The live shape: `Sharing::attachTo('songs', Song::class)` defines
    // `request-songs-access` and checks it against the Song. `formatAbilityToMethod()` camelizes
    // on hyphens, so the policy is asked for `requestFoldersAccess`.
    Gate::define('request-folders-access', fn (User $user, AttributedFolder $folder) => $folder->user_id !== $user->getKey());

    $folder = AttributedFolder::create(['user_id' => $this->owner->id]);

    expect(Gate::forUser($this->other)->allows('request-folders-access', $folder))->toBeTrue()
        ->and(Gate::forUser($this->owner)->allows('request-folders-access', $folder))->toBeFalse();
});

it('lets a DOTTED custom ability reach its Gate::define instead of being shadowed by the policy', function () {
    CascadePolicyRegistrar::register(AttributedFolder::class);

    // `media.ingest`'s shape. A dot is not a hyphen, so `formatAbilityToMethod()` leaves the name
    // alone and the policy is asked for a method literally named `folder.ingest` — never a legal
    // PHP method, and yet `is_callable()` said yes while `__call()` existed.
    Gate::define('folder.ingest', fn (User $user, AttributedFolder $folder) => $folder->user_id === $user->getKey());

    $folder = AttributedFolder::create(['user_id' => $this->owner->id]);

    expect(Gate::forUser($this->owner)->allows('folder.ingest', $folder))->toBeTrue()
        ->and(Gate::forUser($this->other)->allows('folder.ingest', $folder))->toBeFalse();
});

it('still denies a custom ability that no Gate::define declares', function () {
    CascadePolicyRegistrar::register(AttributedFolder::class);

    $folder = AttributedFolder::create(['user_id' => $this->owner->id]);

    // The deny-default is the whole point of the change being narrow: falling through the policy
    // reaches Laravel's empty callback, not an allow. Even the OWNER gets nothing here.
    expect(Gate::forUser($this->owner)->allows('publish-folder', $folder))->toBeFalse()
        ->and(Gate::forUser($this->other)->allows('publish-folder', $folder))->toBeFalse()
        ->and(Gate::forUser($this->owner)->allows('folder.publish', $folder))->toBeFalse();
});

it('keeps a literal override on a STANDARD ability winning over a same-named Gate::define', function () {
    CascadePolicyRegistrar::register(AttributedNote::class);

    // AttributedNote declares `update: false`. A host define of the same name must not reach the
    // model — the seven standard abilities are real methods, so the policy still wins outright.
    Gate::define('update', fn () => true);

    $note = AttributedNote::create(['user_id' => $this->owner->id]);

    expect(Gate::forUser($this->owner)->allows('update', $note))->toBeFalse()
        ->and(Gate::forUser($this->other)->allows('update', $note))->toBeFalse();
});

it('keeps the base cascade answering an unnamed STANDARD ability over a same-named Gate::define', function () {
    CascadePolicyRegistrar::register(AttributedFolder::class);

    Gate::define('view', fn () => true);

    $folder = AttributedFolder::create(['user_id' => $this->owner->id]);

    expect(Gate::forUser($this->owner)->allows('view', $folder))->toBeTrue()
        ->and(Gate::forUser($this->other)->allows('view', $folder))->toBeFalse();
});
