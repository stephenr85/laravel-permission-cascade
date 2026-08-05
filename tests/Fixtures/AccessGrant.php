<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Rushing\PermissionCascade\Contracts\AccessGrant as AccessGrantContract;
use Rushing\PermissionCascade\Tests\TestCase;

/**
 * The test host's grant model — a plain pivot implementing the package's {@see AccessGrantContract}.
 * The package ships no grant model; a host provides one and registers it via
 * `config('permission-cascade.grant_model')` (done in {@see TestCase}).
 */
class AccessGrant extends Model implements AccessGrantContract
{
    protected $table = 'grants';

    protected $guarded = [];

    public function grantable(): MorphTo
    {
        return $this->morphTo();
    }

    public function grantee(): MorphTo
    {
        return $this->morphTo();
    }
}
