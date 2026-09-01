<?php

use Illuminate\Support\Facades\Log;
use Rushing\PermissionCascade\Facades\PermissionNamer;
use Rushing\PermissionCascade\Support\PermissionNamer as PermissionNamerClass;
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

it('warns once — and does not throw — when a part is still a fully-qualified class name', function () {
    // ADR-0118 decision 7. An un-aliased model's getMorphClass() returns its FQCN, and Str::slug()
    // deletes the backslashes rather than failing, so the token is silently wrong. The repair is to
    // make that audible, NOT to refuse: whether a model is aliased is a fact about the host, which by
    // this estate's rule is an advisory finding.
    Log::spy();

    $namer = new PermissionNamerClass;

    // Called three times with the same offending part — the log must fire exactly once, because
    // BaseModelPolicy calls assemble() up to three times per authorization check and a seeder calls it
    // hundreds of times per run. A per-call warning is a flood, which gets silenced and then misses.
    $first = $namer->assemble('Splicewire\Tower\Models\Entity', 'view');
    $namer->assemble('Splicewire\Tower\Models\Entity', 'create');
    $namer->assemble('Splicewire\Tower\Models\Entity', 'delete');

    // The token itself is UNCHANGED — this commit makes the failure audible, it does not re-spell
    // anything. Any change here would silently move every already-persisted token.
    expect($first)->toBe('splicewiretowermodelsentity.view');

    Log::shouldHaveReceived('warning')
        ->once()
        ->withArgs(fn (string $message, array $context) => str_contains($message, 'un-aliased class')
            && $context['part'] === 'Splicewire\Tower\Models\Entity');
});

it('stays silent for an aliased part, so the warning means something', function () {
    // The control. Without this the test above cannot distinguish "warns on FQCNs" from "warns always".
    Log::spy();

    expect((new PermissionNamerClass)->assemble('widget', 'view'))->toBe('widget.view');

    Log::shouldNotHaveReceived('warning');
});
