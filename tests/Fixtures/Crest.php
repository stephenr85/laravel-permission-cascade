<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;

/**
 * Carries the `user_type`/`user_id` columns but NOT the HasMorphUser trait — proves
 * `Ownership::assign()` works on a model class the caller doesn't own (no trait, no
 * class edit required): the seam is column-shaped, not trait-shaped.
 */
class Crest extends Model
{
    protected $guarded = [];

    protected $table = 'crests';
}
