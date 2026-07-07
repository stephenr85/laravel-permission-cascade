<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasUser;

class Gadget extends Model
{
    use HasUser;

    protected $guarded = [];

    protected $table = 'gadgets';
}
