<?php

use Rushing\PermissionCascade\Tests\Fixtures\Post;
use Rushing\PermissionCascade\Tests\Fixtures\PostPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\PublicReachResolver;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;
use Rushing\PermissionCascade\Tests\Fixtures\VaultPolicy;

/**
 * Tracer 13 — the 2-D visibility substrate: a bound ReachResolver gives the `visibility`
 * tier its meaning (including an anonymous-reachable `public` tier), and the opt-in
 * `listed` flag is the orthogonal discoverability axis. `view()` honours reach; a listed
 * row leaves feeds while staying directly viewable.
 */
beforeEach(function () {
    actingTeam(1);
    $this->owner = User::create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $this->member = User::create(['name' => 'Member', 'email' => 'member@example.test']);
    $this->policy = new PostPolicy;
});

function postIds($policy, $user): array
{
    return $policy->scopeForUser(Post::query(), $user)->pluck('id')->all();
}

// ── Backward-compat: the DEFAULT resolver still has no anonymous reach ──────────────────

it('grants an anonymous viewer nothing under the default reach vocabulary', function () {
    // No bindReach() → DefaultReachResolver. A guest sees no vault, member-tier or not.
    $tenant = Vault::create(['name' => 't', 'user_id' => $this->owner->id, 'visibility' => 'tenant']);
    $platform = Vault::create(['name' => 'p', 'user_id' => $this->owner->id, 'visibility' => 'platform']);
    $policy = new VaultPolicy;

    expect($policy->view(null, $tenant))->toBeFalse()
        ->and($policy->view(null, $platform))->toBeFalse()
        ->and($policy->scopeForUser(Vault::query(), null)->pluck('id')->all())->toBe([]);
});

// ── A host binds a public/anonymous reach vocabulary ────────────────────────────────────

it('lets an anonymous viewer see a public record but not a private one', function () {
    bindReach(new PublicReachResolver);
    $public = Post::create(['name' => 'pub', 'user_id' => $this->owner->id, 'visibility' => 'public', 'listed' => true]);
    $private = Post::create(['name' => 'priv', 'user_id' => $this->owner->id, 'visibility' => 'private']);

    expect($this->policy->view(null, $public))->toBeTrue()
        ->and($this->policy->view(null, $private))->toBeFalse();
});

it('lets an anonymous viewer reach an UNLISTED record directly (public-but-unlisted)', function () {
    bindReach(new PublicReachResolver);
    $unlisted = Post::create(['name' => 'u', 'user_id' => $this->owner->id, 'visibility' => 'unlisted', 'listed' => false]);

    // Reachable by anyone with the URL…
    expect($this->policy->view(null, $unlisted))->toBeTrue();
    // …but never surfaced in a feed.
    expect(postIds($this->policy, null))->not->toContain($unlisted->id);
});

it('lists only public+listed rows to an anonymous viewer', function () {
    bindReach(new PublicReachResolver);
    $listed = Post::create(['name' => 'l', 'user_id' => $this->owner->id, 'visibility' => 'public', 'listed' => true]);
    $hidden = Post::create(['name' => 'h', 'user_id' => $this->owner->id, 'visibility' => 'public', 'listed' => false]);
    $unlisted = Post::create(['name' => 'u', 'user_id' => $this->owner->id, 'visibility' => 'unlisted', 'listed' => false]);
    $private = Post::create(['name' => 'p', 'user_id' => $this->owner->id, 'visibility' => 'private']);

    $ids = postIds($this->policy, null);

    expect($ids)->toContain($listed->id)
        ->and($ids)->not->toContain($hidden->id, $unlisted->id, $private->id);
});

it('keeps the discoverability axis orthogonal: a public+unlisted row is viewable but out of the feed', function () {
    bindReach(new PublicReachResolver);
    // Same reach (public), differing only by the listed flag.
    $shown = Post::create(['name' => 's', 'user_id' => $this->owner->id, 'visibility' => 'public', 'listed' => true]);
    $hidden = Post::create(['name' => 'h', 'user_id' => $this->owner->id, 'visibility' => 'public', 'listed' => false]);

    // Both directly viewable (reach ignores listed)…
    expect($this->policy->view($this->member, $shown))->toBeTrue()
        ->and($this->policy->view($this->member, $hidden))->toBeTrue();
    // …only the listed one is in the member's feed.
    $ids = postIds($this->policy, $this->member);
    expect($ids)->toContain($shown->id)->and($ids)->not->toContain($hidden->id);
});

it('lists the owner\'s own unlisted rows regardless of the listed filter', function () {
    bindReach(new PublicReachResolver);
    grantPermission($this->owner, 'post.own.view');
    $mineHidden = Post::create(['name' => 'mine', 'user_id' => $this->owner->id, 'visibility' => 'unlisted', 'listed' => false]);
    $theirsHidden = Post::create(['name' => 'theirs', 'user_id' => $this->member->id, 'visibility' => 'unlisted', 'listed' => false]);

    $ids = postIds($this->policy, $this->owner->fresh());

    // Own branch ignores listed/tier; the other user's unlisted row stays out.
    expect($ids)->toContain($mineHidden->id)->and($ids)->not->toContain($theirsHidden->id);
});

it('never widens manage via reach — a public tier grants view only', function () {
    bindReach(new PublicReachResolver);
    $public = Post::create(['name' => 'pub', 'user_id' => $this->owner->id, 'visibility' => 'public', 'listed' => true]);

    expect($this->policy->view($this->member, $public))->toBeTrue()
        ->and($this->policy->update($this->member, $public))->toBeFalse();
});

it('still lets a member see a public row in their feed with zero tokens', function () {
    bindReach(new PublicReachResolver);
    $public = Post::create(['name' => 'pub', 'user_id' => $this->owner->id, 'visibility' => 'public', 'listed' => true]);

    expect(postIds($this->policy, $this->member))->toContain($public->id);
});
