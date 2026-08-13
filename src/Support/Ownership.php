<?php

namespace Rushing\PermissionCascade\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasMorphUser;

/**
 * The ONE blessed write path for the `user_type`/`user_id` ownership columns (fork re-lock,
 * setting 1). Works on any model carrying the columns — {@see HasMorphUser} is not required, no
 * class edit needed — so a caller can stamp ownership on a model class it doesn't own.
 *
 * Advisory, not enforced: the columns stay directly writable and the trait's `creating` hook
 * still auto-stamps the authed user; structural enforcement is the custody tripwire. The columns
 * themselves are defined as rebuildable projections of a future custody chain
 * (`rushing/laravel-lineage`) — the chain, once it exists, wins disagreements.
 *
 * `transferOwnership()` is deliberately NOT minted here: the first shipped ownership-transfer
 * feature names it, and must land with event-complete, vocabulary-first, prune-exempt custody
 * capture (appending its event and updating the columns in one transaction).
 */
class Ownership
{
    /**
     * Stamp `$model`'s ownership columns from `$user`. Persists when the model already exists
     * in the database; a not-yet-saved model is only filled (the caller's save persists it).
     */
    public function assign(Model $model, Model|Authenticatable $user): Model
    {
        $model->forceFill([
            'user_type' => $user instanceof Model ? $user->getMorphClass() : get_class($user),
            'user_id' => (string) $user->getAuthIdentifier(),
        ]);

        if ($model->exists) {
            $model->save();
        }

        return $model;
    }
}
