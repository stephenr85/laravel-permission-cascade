<?php

use Illuminate\Support\Facades\Gate;
use Rushing\PermissionCascade\Support\CascadePolicyRegistrar;
use Rushing\PermissionCascade\Tests\Fixtures\AttributedFolder;
use Rushing\PermissionCascade\Tests\Fixtures\AttributedNote;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;

beforeEach(function () {
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->other = User::create(['name' => 'Other', 'email' => 'other@example.test']);
});

it('registers a bare #[UseCascadePolicy] onto the base cascade with no overrides', function () {
    CascadePolicyRegistrar::register(AttributedFolder::class);

    $folder = AttributedFolder::create(['user_id' => $this->owner->id]);

    expect(Gate::forUser($this->owner)->allows('view', $folder))->toBeTrue()
        ->and(Gate::forUser($this->other)->allows('view', $folder))->toBeFalse()
        ->and(Gate::forUser($this->owner)->allows('update', $folder))->toBeTrue()
        ->and(Gate::forUser($this->other)->allows('update', $folder))->toBeFalse();
});

it('applies literal per-ability overrides ahead of the base cascade, leaving unnamed abilities to it', function () {
    CascadePolicyRegistrar::register(AttributedNote::class);

    $note = AttributedNote::create(['user_id' => $this->owner->id]);

    expect(Gate::forUser($this->other)->allows('create', AttributedNote::class))->toBeTrue()
        ->and(Gate::forUser($this->owner)->allows('update', $note))->toBeFalse()
        ->and(Gate::forUser($this->owner)->allows('view', $note))->toBeTrue()
        ->and(Gate::forUser($this->other)->allows('view', $note))->toBeFalse();
});

it('keeps two attributed models from colliding on the shared static default-model-class', function () {
    CascadePolicyRegistrar::register(AttributedNote::class);
    CascadePolicyRegistrar::register(AttributedFolder::class);

    $note = AttributedNote::create(['user_id' => $this->owner->id]);
    $folder = AttributedFolder::create(['user_id' => $this->owner->id]);

    expect(Gate::forUser($this->owner)->allows('view', $note))->toBeTrue()
        ->and(Gate::forUser($this->owner)->allows('view', $folder))->toBeTrue()
        ->and(Gate::forUser($this->owner)->allows('update', $note))->toBeFalse()
        ->and(Gate::forUser($this->owner)->allows('update', $folder))->toBeTrue();
});

it('is a no-op for a model without the attribute', function () {
    expect(CascadePolicyRegistrar::register(Widget::class))->toBeFalse();
});

it('discovers every attributed model under a directory and skips the rest', function () {
    $found = CascadePolicyRegistrar::discover(__DIR__.'/Fixtures', 'Rushing\\PermissionCascade\\Tests\\Fixtures');

    expect($found)->toContain(AttributedNote::class, AttributedFolder::class)
        ->and($found)->not->toContain(Widget::class);
});
