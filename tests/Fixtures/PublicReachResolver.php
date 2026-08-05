<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Rushing\PermissionCascade\Contracts\AccessGrant;
use Rushing\PermissionCascade\Contracts\ReachResolver;

/**
 * A host-style reach vocabulary (what audiostud binds): a `public` tier reachable by
 * anyone including the anonymous viewer, and an `unlisted` tier that is equally reachable
 * per-record but deliberately absent from the listable set — the "reachable by anyone,
 * but not in the feed" pairing. Reach only ever widens *view*; manage stays steward/grant.
 */
class PublicReachResolver implements ReachResolver
{
    public function grants(?string $tier, string $ability, ?Authenticatable $viewer): bool
    {
        if ($ability !== AccessGrant::ABILITY_VIEW) {
            return false;
        }

        return in_array($tier, ['public', 'unlisted'], true);
    }

    public function listableTiers(?Authenticatable $viewer): array
    {
        // `public` surfaces in feeds for everyone (member or guest); `unlisted` never does.
        return ['public'];
    }
}
