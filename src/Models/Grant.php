<?php

namespace Rushing\PermissionCascade\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * An explicit, deny-capable sharing grant — the "share with this user/team" row of the
 * directory-style ACL (see {@see \Rushing\PermissionCascade\Concerns\HasVisibility}).
 *
 * `grantable` = the shared object (a {@see HasVisibility} model). `grantee` = a **User** or a
 * **Role** ("team" is a Role). `ability` ∈ {view, manage} with `manage ⊇ view`; `effect` ∈
 * {allow, deny}. Precedence (nearest-wins, deny-beats-allow at a level) is resolved in the
 * package `BaseModelPolicy`, not here — this is a plain pivot with two morphs.
 *
 * The `grants` table is host-owned (it references tenant objects, so it lives in the host's
 * tenant schema); this model is the package-owned generic reader over it. The host aliases it
 * `grant` in its morph map (ADR-0118).
 *
 * @property string $ability view|manage
 * @property string $effect allow|deny
 */
class Grant extends Model
{
    public const ABILITY_VIEW = 'view';

    public const ABILITY_MANAGE = 'manage';

    public const EFFECT_ALLOW = 'allow';

    public const EFFECT_DENY = 'deny';

    protected $table = 'grants';

    protected $guarded = [];

    public function grantable(): MorphTo
    {
        return $this->morphTo();
    }

    public function grantee(): MorphTo
    {
        return $this->morphTo();
    }
}
