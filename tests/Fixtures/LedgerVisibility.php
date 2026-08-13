<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Rushing\PermissionCascade\Contracts\VisibilityRecord as VisibilityRecordContract;
use Rushing\PermissionCascade\Tests\TestCase;

/**
 * The test host's visibility model — a plain morph row implementing the package's
 * {@see VisibilityRecordContract}. The package ships no visibility model; a host provides one
 * and registers it via `config('permission-cascade.visibility_model')` (done in {@see TestCase}).
 */
class LedgerVisibility extends Model implements VisibilityRecordContract
{
    protected $table = 'ledger_visibilities';

    protected $guarded = [];

    protected $casts = [
        'listed' => 'boolean',
    ];

    public function reachable(): MorphTo
    {
        return $this->morphTo();
    }
}
