<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

/**
 * A steward-owning HasVisibility model that overrides {@see permissionCascadeVisibilityModel()}
 * to hardcode {@see LedgerVisibility} directly, INDEPENDENT of `config('permission-cascade.visibility_model')`.
 * Proves the per-model seam (audiostud's real-world fix after a global config toggle broke an
 * unrelated column-based model — beam-bookmarks' Shelf) works with the global config left null.
 */
class LedgerWithOwnVisibilityModel extends Ledger
{
    protected $table = 'ledgers';

    public static function permissionCascadeVisibilityModel(): ?string
    {
        return LedgerVisibility::class;
    }
}
