<?php

namespace Rushing\PermissionCascade\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

trait HasUserId
{
    use ResolvesUserModel;

    public static function bootHasUserId(): void
    {
        static::creating(function (Model $model) {
            if (! $model->user_id && auth()->check()) {
                $model->user_id = auth()->user()->id;
            }

            return $model;
        });

        static::updating(function (Model $model) {
            if (! $model->user_id && auth()->check()) {
                $model->user_id = auth()->user()->id;
            }

            return $model;
        });
    }

    public function user()
    {
        return $this->belongsTo(static::permissionCascadeUserModel());
    }

    public function scopeWhereUser(Builder $query, Authenticatable|string $user)
    {
        $query->where('user_id', $user instanceof Authenticatable ? $user->id : $user);
    }

    public function scopeWhereCurrentUser(Builder $query)
    {
        return $this->scopeWhereUser($query, auth()->user());
    }
}
