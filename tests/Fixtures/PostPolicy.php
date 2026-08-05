<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

class PostPolicy extends BaseModelPolicy
{
    public static $defaultModelClass = Post::class;
}
