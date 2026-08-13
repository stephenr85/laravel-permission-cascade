<?php

namespace Rushing\PermissionCascade\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use Rushing\PermissionCascade\Concerns\HasVisibility;

/**
 * The visibility seam — an explicit, off-table record of a model's own reach tier (and,
 * optionally, its discoverability flag), for a host that would rather not add a `visibility`
 * column directly to a policied model's own table.
 *
 * The package is **model-free**: it ships this contract and the resolution logic ({@see
 * \Rushing\PermissionCascade\Concerns\HasVisibility}, {@see
 * \Rushing\PermissionCascade\Policies\BaseModelPolicy}) but NOT an Eloquent model — same shape
 * as {@see AccessGrant}. Each host provides its own Eloquent model implementing this interface
 * (owning the table name, casts, and any extra columns) and registers it via
 * `config('permission-cascade.visibility_model')`. When no model is configured,
 * `HasVisibility` falls back to its original column-based behavior (a nullable `visibility`
 * string column on the policied model's own table) — fully backward compatible.
 *
 * `reachable` = the policied object (a {@see HasVisibility}
 * model). `tier` is the same nullable string vocabulary the column path already uses
 * (`private`/`tenant`/`platform`, or a host's own) — NULL, or no record at all, means "no
 * explicit tier here," the off-table equivalent of a NULL column: {@see
 * \Rushing\PermissionCascade\Concerns\HasVisibility::effectiveVisibility()} still walks self →
 * ancestors looking for the first non-null tier. An optional `listed` boolean column plays the
 * same role {@see HasVisibility::visibilityListedColumn()}
 * already names on the column path — a host wanting discoverability off-table names that
 * column (on THIS model) via the same hook.
 *
 * @property string|null $tier
 * @property bool|null $listed
 */
interface VisibilityRecord
{
    public function reachable(): MorphTo;
}
