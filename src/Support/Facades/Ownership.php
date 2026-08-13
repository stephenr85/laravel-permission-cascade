<?php

namespace Rushing\PermissionCascade\Support\Facades;

use Illuminate\Support\Facades\Facade;
use Rushing\PermissionCascade\Support\Ownership as SupportOwnership;

/**
 * @method static \Illuminate\Database\Eloquent\Model assign(\Illuminate\Database\Eloquent\Model $model, \Illuminate\Database\Eloquent\Model|\Illuminate\Contracts\Auth\Authenticatable $user)
 *
 * @see SupportOwnership
 */
class Ownership extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SupportOwnership::class;
    }
}
