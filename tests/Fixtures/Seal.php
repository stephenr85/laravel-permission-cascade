<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasMorphUser;
use Rushing\PermissionCascade\Concerns\HasVisibility;

/**
 * The directory-ACL HasMorphUser fixture: morph-pair ownership PLUS HasVisibility — exercises
 * the steward rung (owner allowed with zero tokens, non-deniable) and scopeForUser's
 * directory-ACL own branch over the morph columns. Stands beside Vault (HasUserId + visibility).
 */
class Seal extends Model
{
    use HasMorphUser;
    use HasVisibility;

    protected $guarded = [];

    protected $table = 'seals';
}
