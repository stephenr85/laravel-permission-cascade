<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Attributes\UseCascadePolicy;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Concerns\HasVisibility;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/** A bare `#[UseCascadePolicy]` fixture with no overrides — stands in for a host's plain owner-scoped model with no ability that needs widening or denying (e.g. audiostud's Timeline Project). */
#[UseCascadePolicy(BaseModelPolicy::class)]
class AttributedFolder extends Model
{
    use HasUserId;
    use HasVisibility;

    protected $guarded = [];

    protected $table = 'attributed_folders';
}
