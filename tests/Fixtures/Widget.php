<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasUserId;

class Widget extends Model
{
    use HasUserId;

    protected $guarded = [];

    protected $table = 'widgets';
}
