<?php

use Rushing\PermissionCascade\Tests\Fixtures\Post;
use Rushing\PermissionCascade\Tests\Fixtures\PostPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\PublicReachResolver;
use Rushing\PermissionCascade\Tests\Fixtures\Reach;
use Rushing\PermissionCascade\Tests\Fixtures\User;

/**
 * A host whose reach vocabulary IS a backed enum (audiostud's Visibility) casts `visibility`
 * to it. HasVisibility must (a) not clobber that cast with its string default, and (b) still
 * hand the cascade a plain string tier (effectiveVisibility coerces the enum) so a
 * ?string-typed ReachResolver never receives an enum.
 */
beforeEach(function () {
    actingTeam(1);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->policy = new PostPolicy;
});

it('preserves the host enum cast on the visibility column', function () {
    $post = Post::create(['user_id' => $this->owner->id, 'visibility' => Reach::Public, 'listed' => true]);

    expect($post->fresh()->visibility)->toBe(Reach::Public);
});

it('coerces the enum to its string value for the reach resolver', function () {
    $post = Post::create(['user_id' => $this->owner->id, 'visibility' => Reach::Public, 'listed' => true]);

    expect($post->effectiveVisibility())->toBe('public');
});

it('resolves reach for an enum-cast host through a string ReachResolver', function () {
    bindReach(new PublicReachResolver); // grants()/listableTiers() are typed ?string
    $public = Post::create(['user_id' => $this->owner->id, 'visibility' => Reach::Public, 'listed' => true]);
    $private = Post::create(['user_id' => $this->owner->id, 'visibility' => Reach::Private]);

    expect($this->policy->view(null, $public))->toBeTrue()
        ->and($this->policy->view(null, $private))->toBeFalse();
});
