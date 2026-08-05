<?php

namespace Rushing\PermissionCascade\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Rushing\PermissionCascade\Contracts\AccessGrant;
use Rushing\PermissionCascade\Contracts\ReachResolver;

/**
 * The default reach vocabulary — the historical `tenant`/`platform` semantics, unchanged:
 *
 *   - `platform` — any authenticated **member** may view; *manage* stays gated on the
 *     platform-admin token (`config('permission-cascade.platform_admin_permission')`),
 *     narrowed by the acting credential's scope.
 *   - `tenant` — any authenticated member may view; manage stays steward + grant only.
 *   - anything else (`private`/NULL/unknown) — no reach widening.
 *
 * There is **no anonymous reach here**: an unauthenticated viewer widens nothing. A host
 * that wants public-to-the-world reach binds its own resolver adding a `public` tier that
 * returns true for a null viewer. This binding is what keeps every current consumer
 * (e.g. splicewire-app) byte-for-byte.
 */
class DefaultReachResolver implements ReachResolver
{
    public function grants(?string $tier, string $ability, ?Authenticatable $viewer): bool
    {
        // Anonymous viewers get nothing from the default vocabulary.
        if ($viewer === null) {
            return false;
        }

        if ($tier === 'platform') {
            if ($ability === AccessGrant::ABILITY_VIEW) {
                return true;
            }

            $perm = config('permission-cascade.platform_admin_permission', 'platform.manage');

            return $viewer->can($perm) && app(CredentialScope::class)->permits($perm);
        }

        if ($tier === 'tenant') {
            return $ability === AccessGrant::ABILITY_VIEW;
        }

        return false;
    }

    public function listableTiers(?Authenticatable $viewer): array
    {
        // The tier-visible set for a member is `tenant` ∪ `platform`; a guest sees none.
        return $viewer === null ? [] : ['tenant', 'platform'];
    }
}
