<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Concerns\HasVisibility;

/**
 * A directory-ACL fixture exercising BOTH visibility axes: reach (the `visibility` tier,
 * given meaning by a bound ReachResolver — here one that adds a `public`/anonymous tier)
 * and discoverability (the opt-in `listed` flag). Stands in for a host's publishable
 * resource (audiostud's Composition).
 */
class Post extends Model
{
    use HasUserId;
    use HasVisibility;

    protected $guarded = [];

    protected $table = 'posts';

    // Cast `visibility` to a backed enum, exactly as an enum-vocabulary host does. This must
    // survive HasVisibility's default string cast, and the cascade must still see the string
    // tier (effectiveVisibility coerces the enum) — see HostEnumCastTest.
    protected $casts = ['listed' => 'boolean', 'visibility' => Reach::class];

    /** Opt into the discoverability axis: `scopeForUser` narrows the tier branch to listed rows. */
    public function visibilityListedColumn(): ?string
    {
        return 'listed';
    }
}
