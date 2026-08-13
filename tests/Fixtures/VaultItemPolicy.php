<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

class VaultItemPolicy extends BaseModelPolicy
{
    public static $defaultModelClass = VaultItem::class;
}
