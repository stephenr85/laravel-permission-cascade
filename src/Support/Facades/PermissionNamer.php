<?php

namespace Rushing\PermissionCascade\Support\Facades;

use Illuminate\Support\Facades\Facade;
use Rushing\PermissionCascade\Support\PermissionNamer as SupportPermissionNamer;

/**
 * @method static string assemble(...$parts)
 * @method static \Illuminate\Support\Collection names($primary, $actions, $qualifiers = [])
 *
 * @see SupportPermissionNamer
 */
class PermissionNamer extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SupportPermissionNamer::class;
    }
}
