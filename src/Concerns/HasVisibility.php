<?php

namespace Rushing\PermissionCascade\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Rushing\PermissionCascade\Models\Grant;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/**
 * Opt a policied model into the directory-style ACL: a nullable `visibility` tier column
 * plus explicit, deny-capable {@see Grant}s. Sits beside {@see HasUser}/{@see HasUserId}
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
        // Cast to a plain string; the tier vocabulary is validated at write time by the host,
        // not by an Eloquent enum cast (keeps the concern free of an app enum dependency).
        $this->mergeCasts(['visibility' => 'string']);
    }

    /** Explicit grants attached directly to this record. */
    public function grants(): MorphMany
    {
        return $this->morphMany(Grant::class, 'grantable');
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

            if ($tier !== null && $tier !== '') {
                return $tier;
            }
        }

        return null;
    }
}
