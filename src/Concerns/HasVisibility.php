<?php

namespace Rushing\PermissionCascade\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Database\Eloquent\Relations\MorphOne;
use LogicException;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/**
 * Opt a policied model into the directory-style ACL: a reach tier (`private | tenant |
 * platform`, a host's own vocabulary permitted) plus explicit, deny-capable {@see AccessGrant}s.
 * Sits beside {@see HasUser}/{@see HasUserId} (steward/attribution) — those answer *who owns
 * this*, this answers *who else may see or manage it, and how it is shared*.
 *
 * The tier is nullable, where **NULL = inherit from the parent** (the directory default); a set
 * value is an explicit tier that stops inheritance. Stored one of two ways, chosen per host via
 * `config('permission-cascade.visibility_model')`:
 *   - **Column** (default, no config needed): a nullable `visibility` string column on the
 *     policied model's own table.
 *   - **Morph** (opt-in): an off-table record via {@see \Rushing\PermissionCascade\Contracts\VisibilityRecord},
 *     for a host that would rather not add a `visibility` column to every policied model's own
 *     table. Model-free, same shape as the grant seam — the host's model owns the table/columns.
 *
 * The package stays **topology-agnostic**: it never walks a `parent_id` itself. A model with a
 * containment parent feeds its ancestor chain by overriding {@see visibilityAncestors()} (e.g.
 * over staudenmeir adjacency-list `ancestors`), and the resolution in {@see BaseModelPolicy}
 * walks the chain this concern exposes.
 */
trait HasVisibility
{
    public function initializeHasVisibility(): void
    {
        // Default the tier column to a plain string — the vocabulary is validated at write
        // time by the host, not by an Eloquent enum cast (keeps the concern free of an app
        // enum dependency). But NEVER clobber a cast the host already declared: a host whose
        // reach vocabulary IS an enum casts `visibility` to that enum (e.g. audiostud's
        // Visibility), and this concern must not fight it. Only merge the string default when
        // the model has not already cast the column.
        if (! array_key_exists('visibility', $this->getCasts())) {
            $this->mergeCasts(['visibility' => 'string']);
        }
    }

    /**
     * Explicit grants attached directly to this record. Resolves the host's grant model
     * (implementing {@see \Rushing\PermissionCascade\Contracts\AccessGrant}) from
     * `config('permission-cascade.grant_model')` — the package ships no model. Throws if the
     * grant rung is used without a configured model; the base cascade (steward + reach tier)
     * works without one.
     */
    public function grants(): MorphMany
    {
        $model = static::permissionCascadeGrantModel();

        if ($model === null) {
            throw new LogicException(
                'permission-cascade: no grant model configured. Set config'
                .' [permission-cascade.grant_model] to an Eloquent model implementing'
                .' Rushing\PermissionCascade\Contracts\AccessGrant to use explicit grants.'
            );
        }

        return $this->morphMany($model, 'grantable');
    }

    /** The configured host grant model class, or null when explicit grants are not wired. */
    public static function permissionCascadeGrantModel(): ?string
    {
        return config('permission-cascade.grant_model');
    }

    /**
     * This model's off-table visibility record — {@see \Rushing\PermissionCascade\Contracts\VisibilityRecord} —
     * when a host has opted into the morph-based seam. Throws if accessed without one configured,
     * same as {@see grants()}; the column path (the default) never calls this.
     */
    public function visibilityRecord(): MorphOne
    {
        $model = static::permissionCascadeVisibilityModel();

        if ($model === null) {
            throw new LogicException(
                'permission-cascade: no visibility model configured. Set config'
                .' [permission-cascade.visibility_model] to an Eloquent model implementing'
                .' Rushing\PermissionCascade\Contracts\VisibilityRecord to store visibility off-table.'
            );
        }

        return $this->morphOne($model, 'reachable');
    }

    /**
     * The visibility model THIS model resolves through, or null when storage stays column-based.
     * Defaults to the global `config('permission-cascade.visibility_model')`, but that config key
     * is a single app-wide toggle with NO per-model granularity — setting it moves EVERY
     * HasVisibility model in the host onto the off-table seam at once, including any vendor
     * package model that still carries a real, populated `visibility` column of its own. A host
     * with mixed usage (some models off-table, some column-based) should NOT set the config key
     * at all; instead, override this method on JUST the models that want the off-table seam
     * (returning a visibility-record class directly) and leave every other HasVisibility model
     * on this trait's own column-based default.
     */
    public static function permissionCascadeVisibilityModel(): ?string
    {
        return config('permission-cascade.visibility_model');
    }

    /**
     * Ancestors for visibility inheritance, **nearest-first, EXCLUDING self**.
     *
     * Topology-agnostic default: no parent chain. A host model with containment overrides
     * this to feed its ancestors (nearest ancestor first), and the resolution inherits both
     * grants and the effective tier up that chain.
     *
     * @return iterable<int, Model>
     */
    public function visibilityAncestors(): iterable
    {
        return [];
    }

    /**
     * Self, then ancestors nearest-first — the ordered chain the resolution walks for both
     * nearest-grant and effective-tier resolution.
     *
     * @return array<int, Model>
     */
    public function visibilityChain(): array
    {
        $ancestors = $this->visibilityAncestors();

        return array_merge([$this], is_array($ancestors) ? $ancestors : iterator_to_array($ancestors));
    }

    /**
     * The effective tier: the nearest explicit tier walking self → ancestors while NULL.
     * Returns null when nothing in the chain sets a tier (treated as most-private: steward +
     * grants only).
     */
    public function effectiveVisibility(): ?string
    {
        foreach ($this->visibilityChain() as $node) {
            $tier = $node->visibilityTier();

            if ($tier !== null && $tier !== '') {
                return $tier;
            }
        }

        return null;
    }

    /**
     * This node's own explicit tier only (no ancestor walk) — column-sourced by default, or
     * read off {@see visibilityRecord()} when a visibility model is configured. Public (not
     * protected): {@see effectiveVisibility()} calls this across chain nodes that may be a
     * DIFFERENT class than the caller (e.g. a Clip's ancestor is a Project) — both merely use
     * this same trait, so a protected method would fail PHP's cross-class visibility check.
     */
    public function visibilityTier(): ?string
    {
        $tier = static::permissionCascadeVisibilityModel() !== null
            ? $this->visibilityRecord?->tier
            : ($this->visibility ?? null);

        // A host may cast the tier to a backed enum (its reach vocabulary); the cascade's tier
        // is always the canonical string, so coerce the enum to its value.
        if ($tier instanceof \BackedEnum) {
            $tier = $tier->value;
        }

        return $tier;
    }

    /**
     * The **discoverability** axis (orthogonal to reach): the column carrying a `listed`
     * flag, or null when this model has no listed axis (the default — off). A host model
     * that wants "reachable but out of feeds" overrides this to name its boolean column;
     * `scopeForUser` then subtracts unlisted rows from the *tier-visible* branch, while the
     * per-record `view()` ignores listed entirely (direct/link access is unaffected).
     */
    public function visibilityListedColumn(): ?string
    {
        return null;
    }

    /**
     * Whether this record is listed (discoverable in feeds). True when the model has no
     * listed axis; otherwise reads the flag column (a null/absent value is treated as
     * listed, so opting in without backfilling does not hide existing rows) — off {@see
     * visibilityRecord()} when a visibility model is configured, else this model's own column.
     */
    public function isListed(): bool
    {
        $column = $this->visibilityListedColumn();

        if ($column === null) {
            return true;
        }

        $source = static::permissionCascadeVisibilityModel() !== null
            ? $this->visibilityRecord
            : $this;

        return (bool) ($source?->{$column} ?? true);
    }

    /**
     * Constrain $query to instances whose OWN (no ancestor walk — matching the listing scope's
     * existing semantics) effective tier is in $tiers, honoring the discoverability axis when
     * {@see visibilityListedColumn()} names one. Column-sourced by default, or via {@see
     * visibilityRecord()} when a visibility model is configured. Used by
     * {@see BaseModelPolicy::scopeForUser()}'s tier-visible branch; callable directly as
     * `Model::query()->reachableInTiers($tiers)` (Eloquent local-scope convention).
     *
     * @param  array<int, string>  $tiers
     */
    public function scopeReachableInTiers($query, array $tiers): void
    {
        $listedColumn = $this->visibilityListedColumn();

        if (($visibilityModel = static::permissionCascadeVisibilityModel()) !== null) {
            // NOT whereHas(): that compiles to a correlated `WHERE outer.id = inner.reachable_id`
            // — a real column-to-column comparison a strict driver (Postgres) rejects when the
            // policied model's key is a native `uuid` column against `reachable_id`'s `varchar`
            // (no implicit cast between those types). Fetching matching ids as a plain array
            // first, then `whereIn` on BOUND values, sidesteps it — the same pattern
            // BaseModelPolicy::grantedGrantableIds() already uses for the identical cross-host
            // uuid/bigint morph-key shape.
            $ids = $visibilityModel::query()
                ->where('reachable_type', $this->getMorphClass())
                ->whereIn('tier', $tiers)
                ->when($listedColumn !== null, fn ($q) => $q->where($listedColumn, true))
                ->pluck('reachable_id');

            $query->whereIn($this->getTable().'.'.$this->getKeyName(), $ids);

            return;
        }

        $table = $this->getTable();
        $query->whereIn("{$table}.visibility", $tiers);
        if ($listedColumn !== null) {
            $query->where("{$table}.{$listedColumn}", true);
        }
    }
}
