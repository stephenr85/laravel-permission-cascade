<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

class LedgerPolicy extends BaseModelPolicy
{
    public static $defaultModelClass = Ledger::class;
}
