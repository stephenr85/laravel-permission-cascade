<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

class WidgetPolicy extends BaseModelPolicy
{
    public static $defaultModelClass = Widget::class;
}
