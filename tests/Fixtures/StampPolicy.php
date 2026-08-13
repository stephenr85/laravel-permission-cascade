<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

class StampPolicy extends BaseModelPolicy
{
    public static $defaultModelClass = Stamp::class;
}
