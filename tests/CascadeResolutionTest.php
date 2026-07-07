<?php

use Rushing\PermissionCascade\Policies\BaseModelPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\Gadget;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;
use Rushing\PermissionCascade\Tests\Fixtures\WidgetPolicy;

beforeEach(function () {
    actingTeam(1);
    $this->user = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->other = User::create(['name' => 'Other', 'email' => 'other@example.test']);
    $this->policy = new WidgetPolicy;
});

it('grants a class-level permission across every instance', function () {
    grantPermission($this->user, 'widget.update');

    $a = Widget::create(['name' => 'a']);
    $b = Widget::create(['name' => 'b']);

    expect($this->policy->update($this->user, $a))->toBeTrue();
    expect($this->policy->update($this->user, $b))->toBeTrue();
});

it('grants an instance-level permission for only that instance', function () {
    $a = Widget::create(['name' => 'a']);
    $b = Widget::create(['name' => 'b']);

    grantPermission($this->user, "widget.{$a->id}.update");

    expect($this->policy->update($this->user, $a))->toBeTrue();
    expect($this->policy->update($this->user, $b))->toBeFalse();
});

it('grants an ownership permission only for records the user owns via user_id', function () {
    grantPermission($this->user, 'widget.own.update');

    $mine = Widget::create(['name' => 'mine', 'user_id' => $this->user->id]);
    $theirs = Widget::create(['name' => 'theirs', 'user_id' => $this->other->id]);

    expect($this->policy->update($this->user, $mine))->toBeTrue();
    expect($this->policy->update($this->user, $theirs))->toBeFalse();
});

it('grants an ownership permission for records owned via the HasUser morph pivot', function () {
    grantPermission($this->user, 'gadget.own.update');

    $mine = Gadget::create(['name' => 'mine']);
    $mine->user()->sync([$this->user->id]);

    $theirs = Gadget::create(['name' => 'theirs']);
    $theirs->user()->sync([$this->other->id]);

    $policy = new class extends BaseModelPolicy
    {
        public static $defaultModelClass = Gadget::class;
    };

    // Authorize freshly-loaded instances (as a route-bound request would), so the
    // ownership pivot is read from the DB rather than a stale create-time cache.
    expect($policy->update($this->user, $mine->fresh()))->toBeTrue();
    expect($policy->update($this->user, $theirs->fresh()))->toBeFalse();
});

it('denies when the user holds no matching permission', function () {
    $a = Widget::create(['name' => 'a', 'user_id' => $this->user->id]);

    expect($this->policy->update($this->user, $a))->toBeFalse();
});
