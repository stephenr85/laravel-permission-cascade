<?php

namespace Rushing\PermissionCascade\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;
use Rushing\PermissionCascade\Facades\Ownership;

/**
 * Single owner via a `user_type`/`user_id` morph pair on the row — sits beside {@see HasUser}
 * (multi-owner via pivot) and {@see HasUserId} (single owner, fixed user model): single-owner
 * cardinality like HasUserId, actor-type flexibility like HasUser. No {@see ResolvesUserModel}
 * needed — the owner may be ANY morphable class, which is the generalization this trait exists for.
 *
 * The relation slot stays literally `user` (not `owner`/`actor`): {@see BaseModelPolicy}
 * hardcodes that slot for the other two ownership traits, and this trait fits it rather than
 * introducing a new naming axis.
 *
 * Writes to the columns route through the one blessed seam, {@see Ownership::assign()} —
 * {@see assignUser()} is delegating sugar over it. The `creating` auto-stamp below is the
 * convenience default for the raw HTTP create path (load-bearing: a particle-resource `store`
 * never passes through an action class, so without it those rows land unowned).
 */
trait HasMorphUser
{
    public static function bootHasMorphUser(): void
    {
        static::creating(function (Model $model) {
            if (! $model->user_type && ! $model->user_id && auth()->check()) {
                $user = auth()->user();
                $model->user_type = $user instanceof Model ? $user->getMorphClass() : get_class($user);
                $model->user_id = (string) $user->getAuthIdentifier();
            }

            return $model;
        });
    }

    public function user(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Delegating sugar over the blessed ownership write path ({@see Ownership::assign()}).
     * Deliberately NOT `transferOwnership()` — that name stays un-minted until the first real
     * transfer feature lands with event-complete custody capture (the custody tripwire).
     */
    public function assignUser(Model|Authenticatable $user): static
    {
        Ownership::assign($this, $user);

        return $this;
    }

    public function scopeWhereUser(Builder $query, Model|Authenticatable $user)
    {
        $query
            ->where('user_type', $user instanceof Model ? $user->getMorphClass() : get_class($user))
            ->where('user_id', (string) $user->getAuthIdentifier());
    }

    public function scopeWhereCurrentUser(Builder $query)
    {
        return $this->scopeWhereUser($query, auth()->user());
    }
}
