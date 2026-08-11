<?php

namespace Rushing\PermissionCascade\Policies;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * The runtime shape behind `#[UseCascadePolicy]`: one shared, reusable policy class configured per
 * model at registration time (by {@see \Rushing\PermissionCascade\Support\CascadePolicyRegistrar}),
 * instead of a hand-written `extends BaseModelPolicy` subclass per model. Sets the instance-level
 * {@see BaseModelPolicy::$modelClass} override so many models can each get their own configured
 * instance without colliding on `$defaultModelClass`'s shared static storage.
 *
 * Each of the seven standard abilities checks `$overrides` first — a literal, unconditional
 * true/false wins outright — and only falls through to the base cascade (steward/grant/reach) when
 * that ability was left unnamed. `__call` extends the same literal-override lookup to any OTHER
 * ability name a caller's `Gate::authorize()` names, since those have no method on the base to fall
 * through to — an unnamed custom ability denies.
 */
class ConfiguredModelPolicy extends BaseModelPolicy
{
    /** @param array<string, bool> $overrides */
    public function __construct(string $modelClass, protected array $overrides = [])
    {
        $this->modelClass = $modelClass;
    }

    public function viewAny(Authenticatable $user)
    {
        return $this->overrides['viewAny'] ?? parent::viewAny($user);
    }

    public function view(?Authenticatable $user, Model $instance)
    {
        return $this->overrides['view'] ?? parent::view($user, $instance);
    }

    public function create(Authenticatable $user)
    {
        return $this->overrides['create'] ?? parent::create($user);
    }

    public function update(Authenticatable $user, Model $instance)
    {
        return $this->overrides['update'] ?? parent::update($user, $instance);
    }

    public function delete(Authenticatable $user, Model $instance)
    {
        return $this->overrides['delete'] ?? parent::delete($user, $instance);
    }

    public function restore(Authenticatable $user, Model $instance)
    {
        return $this->overrides['restore'] ?? parent::restore($user, $instance);
    }

    public function forceDelete(Authenticatable $user, Model $instance)
    {
        return $this->overrides['forceDelete'] ?? parent::forceDelete($user, $instance);
    }

    /** A custom ability (no method above matches it): the literal override, or deny (no cascade to fall back to). */
    public function __call(string $method, array $arguments): bool
    {
        return $this->overrides[$method] ?? false;
    }
}
