<?php

use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;
use Rushing\PermissionCascade\Tests\Fixtures\WidgetPolicy;

beforeEach(function () {
    actingTeam(1);
    $this->user = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->other = User::create(['name' => 'Other', 'email' => 'other@example.test']);
    $this->policy = new WidgetPolicy;

    $this->mine = Widget::create(['name' => 'mine', 'user_id' => $this->user->id]);
    $this->theirs = Widget::create(['name' => 'theirs', 'user_id' => $this->other->id]);
});

it('returns all records with an unqualified view permission', function () {
    grantPermission($this->user, 'widget.view');

    $ids = $this->policy->scopeForUser(Widget::query(), $this->user)->pluck('id');

    expect($ids)->toContain($this->mine->id, $this->theirs->id);
});

it('scopes to owned records with an own.view permission', function () {
    grantPermission($this->user, 'widget.own.view');

    $ids = $this->policy->scopeForUser(Widget::query(), $this->user)->pluck('id')->all();

    expect($ids)->toBe([$this->mine->id]);
});

it('returns nothing without any view permission', function () {
    $ids = $this->policy->scopeForUser(Widget::query(), $this->user)->pluck('id')->all();

    expect($ids)->toBe([]);
});
