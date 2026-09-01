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
 * that ability was left unnamed. Any OTHER ability name is not this policy's business at all, and
 * the reason that is a rule rather than an oversight is on {@see self::STANDARD_ABILITIES}.
 */
class ConfiguredModelPolicy extends BaseModelPolicy
{
    /**
     * Every ability this policy can answer — the seven methods below, and nothing else.
     *
     * ⚠️ **This class deliberately has NO `__call()`, and its absence is load-bearing.** It had one
     * until 2026-09-01 (`return $this->overrides[$method] ?? false`), which silently shadowed every
     * `Gate::define()` whose ability was checked against one of these models.
     *
     * Laravel picks the policy in `Gate::resolvePolicyCallback()`, which tests
     * `is_callable([$policy, $this->formatAbilityToMethod($ability)])`. **`is_callable()` is TRUE for
     * ANY method name whatsoever on an object defining `__call()`** — including a name containing a
     * dot, which is not even a legal PHP method name. So the policy won resolution for abilities it
     * had never heard of, `__call()` answered `false`, and `Gate::define()` was never consulted. Not
     * a fallthrough — a denial. Measured live: `beam-accounts`' `Sharing::attachTo()` defines
     * `request-{key}-access` and checks it against the shared model, so audiostud's `songs`
     * request-access op was permanently 403 for exactly the non-owners it exists to serve.
     *
     * ⚠️ **Returning `null` from `__call()` does NOT fix this** — measured, not reasoned. Selection
     * happens at `is_callable()` time, before a return value exists; once the policy callback is
     * chosen, `Gate::resolveAuthCallback()` has already returned and never reaches
     * `$this->abilities[$ability]`. A `null` result is merely "no opinion", which `allows()` reads as
     * false — the same denial, now undocumented. Only the ABSENCE of `__call()` makes `is_callable()`
     * return false and lets resolution continue on to the defined ability.
     *
     * The cost is that `#[UseCascadePolicy]`'s override list is exactly this list, not a wildcard.
     * {@see \Rushing\PermissionCascade\Support\CascadePolicyRegistrar::register()} refuses any other
     * name at registration rather than accepting one that could never have fired.
     *
     * Deny-by-default is unchanged: an ability no `Gate::define()` declares now falls past the policy
     * to Laravel's empty callback, which is `null` → denied.
     *
     * @see \Rushing\PermissionCascade\Tests\CustomAbilityFallthroughTest
     */
    public const STANDARD_ABILITIES = [
        'viewAny', 'view', 'create', 'update', 'delete', 'restore', 'forceDelete',
    ];

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
}
