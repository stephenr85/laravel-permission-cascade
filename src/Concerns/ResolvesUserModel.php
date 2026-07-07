<?php

namespace Rushing\PermissionCascade\Concerns;

use Illuminate\Foundation\Auth\User as FoundationUser;

/**
 * Resolves the Authenticatable model the ownership traits point at, keeping the
 * cascade host-agnostic: the concrete user class (and any tenancy-conditional
 * switch) is a config concern, not baked into the package.
 */
trait ResolvesUserModel
{
    protected static function permissionCascadeUserModel(): string
    {
        $model = config('permission-cascade.user_model');

        if (is_callable($model)) {
            $model = $model();
        }

        return $model
            ?: config('auth.providers.users.model')
            ?: FoundationUser::class;
    }
}
