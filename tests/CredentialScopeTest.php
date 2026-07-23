<?php

use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;
use Rushing\PermissionCascade\Tests\Fixtures\WidgetPolicy;

beforeEach(function () {
    actingTeam(1);
    $this->user = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->policy = new WidgetPolicy;
});

it('leaves authorization unchanged when no credential-scope is bound (unscoped default)', function () {
    grantPermission($this->user, 'widget.update');
    grantPermission($this->user, 'widget.delete');

    $widget = Widget::create(['name' => 'a']);

    // No resolver bound → NullCredentialScopeResolver → authorize exactly as the principal.
    expect($this->policy->update($this->user, $widget))->toBeTrue();
    expect($this->policy->delete($this->user, $widget))->toBeTrue();
});

it('narrows a granted permission that falls outside the bound credential-scope', function () {
    grantPermission($this->user, 'widget.update');
    grantPermission($this->user, 'widget.delete');

    // Scope grants only widget.update — widget.delete must be subtracted.
    bindScope(['widget.update']);

    $widget = Widget::create(['name' => 'a']);

    expect($this->policy->update($this->user, $widget))->toBeTrue();   // in scope → allowed
    expect($this->policy->delete($this->user, $widget))->toBeFalse();  // out of scope → narrowed to denied
});

it('never grants a permission the principal lacks, even when the scope names it', function () {
    // Scope names widget.update, but the principal was never granted it: the intersection
    // can only subtract, never add. Ceiling stays the principal's authority.
    bindScope(['widget.update']);

    $widget = Widget::create(['name' => 'a']);

    expect($this->policy->update($this->user, $widget))->toBeFalse();
});

it('narrows an own-qualified grant the scope omits', function () {
    grantPermission($this->user, 'widget.own.update');
    bindScope(['widget.update']); // scope names the coarse class permission, not the own-qualified one

    $mine = Widget::create(['name' => 'mine', 'user_id' => $this->user->id]);

    // Principal owns the record and holds widget.own.update, but the acting credential's
    // scope omits that permission-name → denied.
    expect($this->policy->update($this->user, $mine))->toBeFalse();
});
