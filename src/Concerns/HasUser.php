<?php

namespace Rushing\PermissionCascade\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;

trait HasUser
{
    use ResolvesUserModel;

    public static function bootHasUser(): void
    {
        static::saved(function (Model $model) {
            $model->loadMissing('user');
            if (! $model->user->first() && auth()->user()) {
                $model->user()->sync([auth()->user()->id]);
            }
        });
    }

    public function user(): MorphToMany
    {
        return $this->morphToMany(static::permissionCascadeUserModel(), 'userable', null, null, 'user_id');
    }

    public function scopeWhereUser(Builder $query, Authenticatable|string $user)
    {
        $query->whereHas('user', fn ($q) => $q->where('user_id', $user instanceof Authenticatable ? $user->id : $user));
    }
}
