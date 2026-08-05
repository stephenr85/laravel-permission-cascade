<?php

namespace Rushing\PermissionCascade\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use Rushing\PermissionCascade\Concerns\HasVisibility;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/**
 * The grant seam — an explicit, deny-capable sharing row of the directory-style ACL.
 *
 * The package is **model-free**: it ships this contract and the resolution logic
 * ({@see BaseModelPolicy},
 * {@see HasVisibility}) but NOT an Eloquent model. Each
 * host provides its own Eloquent grant model implementing this interface — owning the table
 * name, casts, and any extra columns — and registers it via
 * `config('permission-cascade.grant_model')`. When no model is configured, the grant rung is
 * simply inert: authorization falls back to steward + reach tier (the base cascade still works).
 *
 * `grantable` = the shared object (a {@see HasVisibility}
 * model). `grantee` = a User or a Role ("team" is a Role). `ability` ∈ {view, manage} with
 * `manage ⊇ view`; `effect` ∈ {allow, deny}. Precedence (nearest-wins, deny-beats-allow at a
 * level) is resolved in the policy, not the model — an implementation is a plain pivot with
 * two morphs plus the `ability`/`effect` attributes.
 *
 * @property string $ability view|manage
 * @property string $effect allow|deny
 */
interface AccessGrant
{
    public const ABILITY_VIEW = 'view';

    public const ABILITY_MANAGE = 'manage';

    public const EFFECT_ALLOW = 'allow';

    public const EFFECT_DENY = 'deny';

    public function grantable(): MorphTo;

    public function grantee(): MorphTo;
}
