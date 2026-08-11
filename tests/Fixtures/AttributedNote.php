<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Attributes\UseCascadePolicy;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Concerns\HasVisibility;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/** A `#[UseCascadePolicy]` fixture carrying literal overrides — stands in for a host's owner-only, immutable-once-written model (e.g. audiostud's AudioSample). */
#[UseCascadePolicy(BaseModelPolicy::class, create: true, update: false)]
class AttributedNote extends Model
{
    use HasUserId;
    use HasVisibility;

    protected $guarded = [];

    protected $table = 'attributed_notes';
}
