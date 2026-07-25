<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Concerns\HasVisibility;

/**
 * A directory-ACL fixture: steward via HasUserId, tiers + grants via HasVisibility, and a
 * self-referential `parent_id` containment chain so inheritance (nearest-grant + effective
 * tier walking up while NULL) can be exercised. Stands in for a host's Silo/Thread.
 */
class Vault extends Model
{
    use HasUserId;
    use HasVisibility;

    protected $guarded = [];

    protected $table = 'vaults';

    public function parent(): BelongsTo
    {
        return $this->belongsTo(Vault::class, 'parent_id');
    }

    /** Nearest-first ancestor chain (the host feeds this; the package never walks it). */
    public function visibilityAncestors(): iterable
    {
        $ancestors = [];
        $node = $this->parent;

        while ($node) {
            $ancestors[] = $node;
            $node = $node->parent;
        }

        return $ancestors;
    }
}
