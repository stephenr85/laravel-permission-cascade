<?php

namespace Rushing\PermissionCascade\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Rushing\PermissionCascade\Concerns\HasVisibility;
use Rushing\PermissionCascade\Support\DefaultReachResolver;

/**
 * The reach seam — the *audience-breadth* axis of visibility.
 *
 * A record's `visibility` tier is a host-defined string. This resolver is the one place
 * that string is given meaning: for a tier, does it widen access to a given viewer? The
 * cascade never hardcodes a tier vocabulary; it consults this. The package ships a
 * {@see DefaultReachResolver} that reproduces the
 * historical `tenant`/`platform` semantics, so an unbound host is unchanged. A host binds
 * its own resolver (via `config('permission-cascade.reach_resolver')` or by rebinding this
 * contract) to add tiers — e.g. a `public` tier that widens to the **anonymous** viewer.
 *
 * Reach answers *how broad is the audience*. It is orthogonal to **discoverability**
 * (listed vs link-only), which {@see HasVisibility}
 * carries as an opt-in `listed` flag: a tier may widen a per-record {@see grants()} view
 * yet be absent from {@see listableTiers()} — that pairing is exactly "reachable by
 * anyone, but not in the feed."
 */
interface ReachResolver
{
    /**
     * Per-record widening: does reach tier `$tier`, on its own, grant `$ability` to
     * `$viewer` (null = an anonymous/guest viewer)? Return true to widen (allow); false to
     * fall through to steward + explicit grants only. This is consulted after the steward
     * and grant rungs, so it can only ever *add* access.
     */
    public function grants(?string $tier, string $ability, ?Authenticatable $viewer): bool;

    /**
     * Listing widening: the reach tiers whose *view* is open to `$viewer` (null = guest),
     * folded into `scopeForUser` as `whereIn('visibility', [...])`. Return `[]` for none.
     * A tier that grants a per-record view but should stay out of feeds is deliberately
     * omitted here (the "unlisted" pairing).
     *
     * @return array<int, string>
     */
    public function listableTiers(?Authenticatable $viewer): array;
}
