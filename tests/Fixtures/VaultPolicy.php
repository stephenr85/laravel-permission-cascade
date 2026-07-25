<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

class VaultPolicy extends BaseModelPolicy
{
    public static $defaultModelClass = Vault::class;
}
