<?php

namespace Rushing\PermissionCascade\Attributes;

use Attribute;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/**
 * Declares a model's authorization on the model itself, for the common case where a
 * {@see BaseModelPolicy}-shaped policy needs nothing beyond the steward rung plus a handful of
 * literal per-ability overrides — no hand-written Policy file. {@see \Rushing\PermissionCascade\Support\CascadePolicyRegistrar}
 * reads this off the model (via reflection) and wires the Gate binding; it never fires on its own —
 * a host must still call `CascadePolicyRegistrar::register()`/`registerMany()`/`registerDiscovered()`.
 *
 * `$overrides` is a wildcard, not a fixed ability list: any named bool argument beyond `policy`
 * becomes a literal, unconditional answer for that ability — `create: true` always allows,
 * `update: false` always denies — for the seven standard abilities (`viewAny`/`view`/`create`/
 * `update`/`delete`/`restore`/`forceDelete`) AND any other ability name a caller's `Gate::authorize()`
 * names (via {@see \Rushing\PermissionCascade\Policies\ConfiguredModelPolicy::__call()}). Every
 * ability left unnamed falls through to `$policy`'s own resolution (the steward/grant/reach
 * cascade). This only ever expresses UNCONDITIONAL overrides — an ability whose answer depends on
 * the model instance (e.g. "allow update only while status=draft") still needs a real Policy class.
 *
 * `$policy` must be `BaseModelPolicy` or a subclass — `ConfiguredModelPolicy` extends it and needs
 * the cascade machinery (`canCascade`/`resolveShared`/`isSteward`) the override methods fall back to.
 *
 * Example: `#[UseCascadePolicy(BaseModelPolicy::class, create: true, update: false)]` on a model.
 */
#[Attribute(Attribute::TARGET_CLASS)]
class UseCascadePolicy
{
    /** @var array<string, bool> */
    public readonly array $overrides;

    public function __construct(
        public readonly string $policy = BaseModelPolicy::class,
        bool ...$overrides,
    ) {
        $this->overrides = $overrides;
    }
}
