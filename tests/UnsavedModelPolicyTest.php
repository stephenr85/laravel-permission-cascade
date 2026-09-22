<?php

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\Gadget;
use Rushing\PermissionCascade\Tests\Fixtures\Post;
use Rushing\PermissionCascade\Tests\Fixtures\PostPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\PublicReachResolver;
use Rushing\PermissionCascade\Tests\Fixtures\Stamp;
use Rushing\PermissionCascade\Tests\Fixtures\StampPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;
use Rushing\PermissionCascade\Tests\Fixtures\WidgetPolicy;

beforeEach(function () {
    actingTeam(1);
    $this->user = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->gadgetPolicy = new class extends BaseModelPolicy
    {
        public static $defaultModelClass = Gadget::class;
    };
});

it('does not query ownership for an unsaved membership-owned prototype', function () {
    grantPermission($this->user, 'gadget.own.update');
    DB::enableQueryLog();
    DB::flushQueryLog();

    expect($this->gadgetPolicy->update($this->user, new Gadget))->toBeFalse();

    $ownershipQueries = collect(DB::getQueryLog())
        ->filter(fn (array $query): bool => str_contains($query['query'], 'userables'));
    expect($ownershipQueries)->toHaveCount(0);
});

it('can deny a prototype when its ownership table is not installed', function () {
    grantPermission($this->user, 'gadget.own.update');
    // This fixture connection is SQLite :memory:, recreated for each test.
    expect(DB::connection()->getDriverName())->toBe('sqlite')
        ->and(DB::connection()->getDatabaseName())->toBe(':memory:');
    Schema::drop('userables');

    expect($this->gadgetPolicy->update($this->user, new Gadget))->toBeFalse();
});

it('does not grant ownership from an unsaved models loaded owner relation', function () {
    grantPermission($this->user, 'gadget.own.update');
    $prototype = new Gadget;
    $prototype->setRelation('user', collect([$this->user]));

    expect($this->gadgetPolicy->update($this->user, $prototype))->toBeFalse();
});

it('does not grant scalar ownership before persistence', function () {
    grantPermission($this->user, 'widget.own.update');
    $prototype = new Widget(['user_id' => $this->user->id]);

    expect((new WidgetPolicy)->update($this->user, $prototype))->toBeFalse();
});

it('does not grant inherent morph stewardship before persistence', function () {
    $prototype = new Stamp([
        'user_type' => $this->user->getMorphClass(),
        'user_id' => $this->user->id,
    ]);

    expect((new StampPolicy)->delete($this->user, $prototype))->toBeFalse();
});

it('does not mistake a preassigned key for a persisted instance', function () {
    $prototype = new Widget(['id' => 777]);
    grantPermission($this->user, 'widget.777.update');

    expect($prototype->exists)->toBeFalse()
        ->and((new WidgetPolicy)->update($this->user, $prototype))->toBeFalse();
});

it('does not resolve public reach or grants on an unsaved ACL model', function (bool $anonymous) {
    bindReach(new PublicReachResolver);
    $prototype = new Post(['visibility' => 'public']);
    DB::enableQueryLog();
    DB::flushQueryLog();

    expect((new PostPolicy)->view($anonymous ? null : $this->user, $prototype))->toBeFalse();

    $grantQueries = collect(DB::getQueryLog())
        ->filter(fn (array $query): bool => str_contains($query['query'], '"grants"'));
    expect($grantQueries)->toHaveCount(0);
})->with([false, true]);

it('retains class authority for a prototype and the credential scope ceiling', function () {
    grantPermission($this->user, 'widget.update');
    $policy = new WidgetPolicy;
    $prototype = new Widget;

    expect($policy->update($this->user, $prototype))->toBeTrue();
    bindScope(['widget.view']);
    expect($policy->update($this->user, $prototype))->toBeFalse();
});

it('keeps create and viewAny on their declared class permissions', function () {
    grantPermission($this->user, 'widget.create');
    grantPermission($this->user, 'widget.own.view');
    $policy = new WidgetPolicy;

    expect($policy->create($this->user))->toBeTrue()
        ->and($policy->viewAny($this->user))->toBeTrue();
    bindScope([]);
    expect($policy->create($this->user))->toBeFalse()
        ->and($policy->viewAny($this->user))->toBeFalse();
});

it('still authorizes persisted membership owners and denies non-owners', function () {
    grantPermission($this->user, 'gadget.own.update');
    $mine = Gadget::create(['name' => 'Mine']);
    $mine->user()->sync([$this->user->id]);
    $other = Gadget::create(['name' => 'Other']);

    expect($this->gadgetPolicy->update($this->user, $mine->fresh()))->toBeTrue()
        ->and($this->gadgetPolicy->update($this->user, $other->fresh()))->toBeFalse();
});

it('still exposes missing ownership storage when authorizing a persisted record', function () {
    grantPermission($this->user, 'gadget.own.update');
    $record = Gadget::create(['name' => 'Persisted'])->fresh();
    Schema::drop('userables');

    expect(fn () => $this->gadgetPolicy->update($this->user, $record))
        ->toThrow(QueryException::class);
});
