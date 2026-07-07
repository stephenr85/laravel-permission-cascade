<?php

use Rushing\PermissionCascade\Support\Facades\PermissionNamer;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;

it('assembles a class-level permission from a model class string', function () {
    expect(PermissionNamer::assemble(Widget::class, 'update'))->toBe('widget.update');
});

it('assembles an instance-level permission from a model instance', function () {
    $widget = Widget::create(['name' => 'a']);

    expect(PermissionNamer::assemble($widget, 'update'))->toBe("widget.{$widget->id}.update");
});

it('assembles an ownership-qualified permission', function () {
    expect(PermissionNamer::assemble(Widget::class, 'own', 'update'))->toBe('widget.own.update');
});

it('slugs multi-segment dotted parts', function () {
    expect(PermissionNamer::assemble('Some.Nested', 'Force Delete'))->toBe('some.nested.force-delete');
});

it('expands names() over actions and qualifiers', function () {
    $names = PermissionNamer::names(Widget::class, ['view', 'update'])->all();

    expect($names)->toBe(['widget.view', 'widget.update']);
});
