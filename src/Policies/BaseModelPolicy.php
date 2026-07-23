<?php

namespace Rushing\PermissionCascade\Policies;

use Illuminate\Auth\Access\HandlesAuthorization;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasUser;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Support\CredentialScope;
use Rushing\PermissionCascade\Support\Facades\PermissionNamer;

class BaseModelPolicy
{
    use HandlesAuthorization;

    public static $defaultModelClass = Model::class;

    /**
     * A single cascade permission check, narrowed by the acting credential's scope.
     *
     * This is the one place the intersection is applied: the principal must hold the
     * permission (`$user->can`) AND the acting credential's scope must permit it. Unscoped
     * credentials pass through unchanged, so this is byte-for-byte today's behaviour until
     * a host binds a narrowing CredentialScopeResolver. Narrow-only: a scope can subtract
     * a permission but never grant one `$user->can` denies.
     */
    protected function permits($user, string $permission): bool
    {
        return $user->can($permission)
            && app(CredentialScope::class)->permits($permission);
    }

    protected function canCascade($user, Model|string $model, $action)
    {
        if (is_string($model)) {
            $modelClass = $model;
            $model = null;
        } else {
            $modelClass = get_class($model);
        }
        // modelClass.action
        if ($this->permits($user, PermissionNamer::assemble($modelClass, $action))) {
            return true;
        }

        if ($model) {
            // modelClass.id.action
            if ($this->permits($user, PermissionNamer::assemble($model, $action))) {
                return true;
            }

            // modelClass.own.action
            if ($this->permits($user, PermissionNamer::assemble($modelClass, 'own', $action))) {
                $classes = class_uses_recursive($model);
                if (in_array(HasUser::class, $classes)) {
                    $model->loadMissing('user');
                    // HasUser::user() is a morphToMany, so `user` is a collection —
                    // ownership is membership, not a scalar id comparison.
                    if ($model->user->contains('id', $user->id)) {
                        return true;
                    }
                } elseif (in_array(HasUserId::class, $classes)) {
                    if ($model->user_id == $user->id) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Scope a query to only include records the user is authorized to view.
     * Model.view = all records, Model.own.view = only the user's records.
     */
    public function scopeForUser($query, Authenticatable $user)
    {
        $modelClass = static::$defaultModelClass;

        // If user has unqualified view, no scoping needed
        if ($this->permits($user, PermissionNamer::assemble($modelClass, 'view'))) {
            return $query;
        }

        // If user has own.view, scope to their records
        if ($this->permits($user, PermissionNamer::assemble($modelClass, 'own', 'view'))) {
            $classes = class_uses_recursive($modelClass);
            if (in_array(HasUserId::class, $classes)) {
                return $query->where('user_id', $user->id);
            } elseif (in_array(HasUser::class, $classes)) {
                return $query->whereHas('user', fn ($q) => $q->where('user_id', $user->id));
            }
        }

        // No view permission at all — return nothing
        return $query->whereRaw('1 = 0');
    }

    public function viewAny(Authenticatable $user)
    {
        return $this->permits($user, PermissionNamer::assemble(static::$defaultModelClass, 'view'))
            || $this->permits($user, PermissionNamer::assemble(static::$defaultModelClass, 'own', 'view'));
    }

    public function view(?Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'view');
    }

    public function create(Authenticatable $user)
    {
        return $this->permits($user, PermissionNamer::assemble(static::$defaultModelClass, 'create'));
    }

    public function update(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'update');
    }

    public function delete(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'delete');
    }

    public function restore(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'restore');
    }

    public function forceDelete(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'force-delete');
    }
}
