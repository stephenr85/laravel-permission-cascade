<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Rushing\PermissionCascade\Concerns\HasVisibility;

/**
 * A steward-climb fixture (ticket 07): carries no owner trait of its own — only a containing
 * Vault does — standing in for `rushing/audiostud`'s `Timeline\Clip` (owned only via
 * `track.project.user_id`). `visibilityAncestors()` names the owning Vault directly, mirroring
 * Clip's own single-hop override rather than walking every intermediate node.
 */
class VaultItem extends Model
{
    use HasVisibility;

    protected $guarded = [];

    protected $table = 'vault_items';

    public function vault(): BelongsTo
    {
        return $this->belongsTo(Vault::class);
    }

    public function visibilityAncestors(): iterable
    {
        return [$this->vault];
    }
}
