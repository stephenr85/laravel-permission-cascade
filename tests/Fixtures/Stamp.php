<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasMorphUser;

/**
 * The HasMorphUser fixture (consumer-agnostic noun, vault-item precedent): a single
 * polymorphic owner via `user_type`/`user_id` columns on the row, NO directory ACL —
 * exercises the token-gated `.own.` rung and the legacy scopeForUser path.
 */
class Stamp extends Model
{
    use HasMorphUser;

    protected $guarded = [];

    protected $table = 'stamps';
}
