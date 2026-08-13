<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

class SealPolicy extends BaseModelPolicy
{
    public static $defaultModelClass = Seal::class;
}
