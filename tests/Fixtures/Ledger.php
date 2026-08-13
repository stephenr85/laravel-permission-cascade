<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Concerns\HasVisibility;

/**
 * The visibility-model-seam fixture: steward via HasUserId, tiers + grants via HasVisibility,
 * self-referential `parent_id` containment (mirrors Vault) — but its own table (`ledgers`)
 * carries NO `visibility`/`listed` column at all. Proves the morph seam
 * (`config('permission-cascade.visibility_model')`) needs no schema change to the policied
 * model's own table.
 */
class Ledger extends Model
{
    use HasUserId;
    use HasVisibility;

    protected $guarded = [];

    protected $table = 'ledgers';

    public function parent(): BelongsTo
    {
        return $this->belongsTo(Ledger::class, 'parent_id');
    }

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

    public function visibilityListedColumn(): ?string
    {
        return 'listed';
    }
}
