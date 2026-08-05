<?php

namespace Rushing\PermissionCascade\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use LogicException;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/**
 * Opt a policied model into the directory-style ACL: a nullable `visibility` tier column
 * plus explicit, deny-capable {@see AccessGrant}s. Sits beside {@see HasUser}/{@see HasUserId}
 * (steward/attribution) — those answer *who owns this*, this answers *who else may see or
 * manage it, and how it is shared*.
 *
 * The tier column is `private | tenant | platform`, nullable, where **NULL = inherit from
 * the parent** (the directory default); a set value is an explicit tier that stops
 * inheritance. The package stays **topology-agnostic**: it never walks a `parent_id` itself.
 * A model with a containment parent feeds its ancestor chain by overriding
 * {@see visibilityAncestors()} (e.g. over staudenmeir adjacency-list `ancestors`), and the
 * resolution in {@see BaseModelPolicy} walks the chain
 * this concern exposes.
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
     * The effective tier: the nearest explicit `visibility` walking self → ancestors while
     * NULL. Returns null when nothing in the chain sets a tier (treated as most-private:
     * steward + grants only).
     */
    public function effectiveVisibility(): ?string
    {
        foreach ($this->visibilityChain() as $node) {
            $tier = $node->visibility ?? null;

            // A host may cast `visibility` to a backed enum (its reach vocabulary); the
            // cascade's tier is always the canonical string, so coerce the enum to its value.
            if ($tier instanceof \BackedEnum) {
                $tier = $tier->value;
            }

            if ($tier !== null && $tier !== '') {
                return $tier;
            }
        }

        return null;
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
     * listed, so opting in without backfilling does not hide existing rows).
     */
    public function isListed(): bool
    {
        $column = $this->visibilityListedColumn();

        return $column === null ? true : (bool) ($this->{$column} ?? true);
    }
}
