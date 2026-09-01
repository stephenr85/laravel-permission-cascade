<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Attributes\UseCascadePolicy;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/**
 * A declaration the attribute USED to accept and silently break: `publish` is not one of the seven
 * abilities {@see \Rushing\PermissionCascade\Policies\ConfiguredModelPolicy} can answer, so the
 * literal `true` here could only ever have been served by the removed `__call()` — the same magic
 * method that shadowed the host's `Gate::define()`. Registration must refuse it outright.
 */
#[UseCascadePolicy(BaseModelPolicy::class, publish: true)]
class AttributedBadge extends Model
{
    use HasUserId;

    protected $guarded = [];

    protected $table = 'attributed_badges';
}
