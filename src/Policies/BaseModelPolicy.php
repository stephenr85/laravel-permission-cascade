<?php

namespace Rushing\PermissionCascade\Policies;

use Illuminate\Auth\Access\HandlesAuthorization;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Rushing\PermissionCascade\Concerns\HasUser;
use Rushing\PermissionCascade\Concerns\HasUserId;
use Rushing\PermissionCascade\Concerns\HasVisibility;
use Rushing\PermissionCascade\Contracts\ReachResolver;
use Rushing\PermissionCascade\Models\Grant;
use Rushing\PermissionCascade\Support\CredentialScope;
use Rushing\PermissionCascade\Support\Facades\PermissionNamer;

class BaseModelPolicy
{
    use HandlesAuthorization;

    public static $defaultModelClass = Model::class;

    /**
     * A single cascade permission check, narrowed by the acting credential's scope.
     *
     * This is the one place the intersection is applied: the principal must hold the
     * permission (`$user->can`) AND the acting credential's scope must permit it. Unscoped
     * credentials pass through unchanged, so this is byte-for-byte today's behaviour until
     * a host binds a narrowing CredentialScopeResolver. Narrow-only: a scope can subtract
     * a permission but never grant one `$user->can` denies.
     */
    protected function permits($user, string $permission): bool
    {
        return $user->can($permission)
            && app(CredentialScope::class)->permits($permission);
    }

    protected function canCascade($user, Model|string $model, $action)
    {
        if (is_string($model)) {
            $modelClass = $model;
            $model = null;
        } else {
            $modelClass = get_class($model);
        }

        // An anonymous (null) principal holds no permission tokens, so every token rung
        // below would fatal on `$user->can`. Only the shared/reach rung can widen access
        // to a guest, and only for an instance.
        if ($user === null) {
            return $model ? $this->resolveShared(null, $model, $action) : false;
        }

        // modelClass.action
        if ($this->permits($user, PermissionNamer::assemble($modelClass, $action))) {
            return true;
        }

        if ($model) {
            // modelClass.id.action
            if ($this->permits($user, PermissionNamer::assemble($model, $action))) {
                return true;
            }

            // modelClass.own.action
            if ($this->permits($user, PermissionNamer::assemble($modelClass, 'own', $action))) {
                $classes = class_uses_recursive($model);
                if (in_array(HasUser::class, $classes)) {
                    $model->loadMissing('user');
                    // HasUser::user() is a morphToMany, so `user` is a collection —
                    // ownership is membership, not a scalar id comparison.
                    if ($model->user->contains('id', $user->id)) {
                        return true;
                    }
                } elseif (in_array(HasUserId::class, $classes)) {
                    if ($model->user_id == $user->id) {
                        return true;
                    }
                }
            }

            // modelClass.shared.action — the directory-style ACL rung (ticket 14): explicit,
            // deny-capable grants + nullable-inheritance visibility tiers. Purely ADDITIVE
            // beside the token rungs above: it only ever grants access the tokens didn't, and
            // its deny semantics are internal to grant resolution (a nearer deny beats an
            // inherited allow) — a deny never revokes a class/instance/steward token above,
            // which stay non-deniable (anti-lockout). A no-op for models without HasVisibility.
            if ($this->resolveShared($user, $model, $action)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Effective-access resolution for the `.shared.` rung (ticket 14 / ADR directory ACL):
     * for actor $user, object $model, ability derived from $action, first rule that fires wins.
     *
     *   1. Steward — the object's `user_id`/HasUser owner. **Inherent and non-deniable** (10's
     *      anti-lockout rule): the owner always retains manage, with no `.own.` token required
     *      and no deny able to wall them out. Broader than the token-gated `.own.` rung above.
     *   2. Nearest explicit grant — walk self → ancestors; the nearest level with a grant
     *      matching the user (direct, or via a Role they hold) decides, and deny beats allow
     *      at that level.
     *   3. Effective reach tier — no grant → resolve `visibility` walking up while NULL, then
     *      hand the tier to the bound {@see ReachResolver}. The default resolver keeps the
     *      historical platform/tenant semantics; a host resolver may widen a tier to an
     *      anonymous ($user === null) viewer.
     *   4. else deny.
     *
     * `$user` may be null (an anonymous viewer): the steward and grant rungs need an
     * identified principal and are skipped, so a guest reaches the tier rung directly.
     */
    protected function resolveShared($user, Model $model, string $action): bool
    {
        if (! in_array(HasVisibility::class, class_uses_recursive($model), true)) {
            return false;
        }

        $ability = $action === 'view' ? Grant::ABILITY_VIEW : Grant::ABILITY_MANAGE;

        // Rules 1–2 require an identified principal; an anonymous viewer skips to the tier.
        if ($user !== null) {
            // Rule 1 — steward is inherent and non-deniable (checked before any grant).
            if ($this->isSteward($user, $model)) {
                return true;
            }

            // Rule 2 — nearest explicit grant (deny beats allow at a level).
            foreach ($model->visibilityChain() as $node) {
                $decision = $this->grantDecisionAt($node, $user, $ability);
                if ($decision !== null) {
                    return $decision;
                }
            }
        }

        // Rule 3 — effective reach tier, resolved by the bound ReachResolver.
        return app(ReachResolver::class)->grants($model->effectiveVisibility(), $ability, $user);
    }

    /** Whether $user is the record's steward (its HasUserId `user_id` or a HasUser member). */
    protected function isSteward($user, Model $model): bool
    {
        $classes = class_uses_recursive($model);

        if (in_array(HasUser::class, $classes, true)) {
            $model->loadMissing('user');

            return $model->user->contains('id', $user->id);
        }

        if (in_array(HasUserId::class, $classes, true)) {
            return $model->user_id == $user->id;
        }

        return false;
    }

    /**
     * The grant decision at a single level: null = no matching grant here (fall through to the
     * next ancestor / tier), true = allow wins, false = deny wins. `manage ⊇ view`: an allow
     * grant covers any ability at or below its rank; a deny covers any ability at or above it
     * (deny(view) also blocks manage; deny(manage) does not block view).
     */
    protected function grantDecisionAt(Model $node, $user, string $ability): ?bool
    {
        if (! in_array(HasVisibility::class, class_uses_recursive($node), true)) {
            return null;
        }

        $grants = $node->grants()
            ->where(fn ($q) => $this->whereGrantee($q, $user))
            ->get(['ability', 'effect']);

        if ($grants->isEmpty()) {
            return null;
        }

        $rank = [Grant::ABILITY_VIEW => 1, Grant::ABILITY_MANAGE => 2];
        $req = $rank[$ability];

        $covering = $grants->filter(function ($g) use ($rank, $req) {
            $gr = $rank[$g->ability] ?? 1;

            return $g->effect === Grant::EFFECT_DENY ? $gr <= $req : $gr >= $req;
        });

        if ($covering->isEmpty()) {
            return null;
        }

        return $covering->contains(fn ($g) => $g->effect === Grant::EFFECT_DENY) ? false : true;
    }

    /**
     * Constrain a grants query to rows granted to this user — directly, or via any Role the
     * user holds (a "team" is a Role). Shared by per-record resolution and scopeForUser.
     */
    protected function whereGrantee($query, $user): void
    {
        $query->where(function ($q) use ($user) {
            $q->where('grantee_type', $user->getMorphClass())->where('grantee_id', $user->getKey());

            foreach ($this->granteeRoleTuples($user) as $type => $ids) {
                $q->orWhere(fn ($qq) => $qq->where('grantee_type', $type)->whereIn('grantee_id', $ids));
            }
        });
    }

    /** The user's roles grouped morph-type => [ids], for role-based grant matching. */
    protected function granteeRoleTuples($user): array
    {
        if (! method_exists($user, 'roles')) {
            return [];
        }

        return $user->roles
            ->groupBy(fn ($r) => $r->getMorphClass())
            ->map(fn ($group) => $group->pluck('id')->all())
            ->all();
    }

    /**
     * Grantable ids reachable from a direct grant of the given effect for a view listing.
     * allow → ability in {view, manage} (manage ⊇ view); deny → ability view only
     * (a manage-deny doesn't hide a row from a view listing).
     *
     * First-cut approximation: DIRECT grants on the record only — ancestor-inherited grants
     * are resolved by the per-record `view` policy, not folded into the listing query (that
     * needs the host's recursive topology; see the ADR).
     *
     * @return array<int, int|string>
     */
    protected function grantedGrantableIds(string $grantableMorph, $user, string $effect): array
    {
        $query = Grant::query()
            ->where('grantable_type', $grantableMorph)
            ->where('effect', $effect)
            ->where(fn ($q) => $this->whereGrantee($q, $user));

        $effect === Grant::EFFECT_ALLOW
            ? $query->whereIn('ability', [Grant::ABILITY_VIEW, Grant::ABILITY_MANAGE])
            : $query->where('ability', Grant::ABILITY_VIEW);

        return $query->pluck('grantable_id')->all();
    }

    /**
     * Scope a query to only include records the viewer is authorized to view.
     * Model.view = all records, Model.own.view = only the viewer's records, plus the
     * reach-listable tiers (resolved by the bound {@see ReachResolver}) and direct
     * allow-grants, minus direct deny-grants. `$user` may be null (an anonymous viewer):
     * a guest sees only the tiers the resolver lists for a null viewer, and only rows
     * that are `listed` when the model carries a discoverability flag.
     */
    public function scopeForUser($query, ?Authenticatable $user = null)
    {
        $modelClass = static::$defaultModelClass;
        $classes = class_uses_recursive($modelClass);
        $hasVisibility = in_array(HasVisibility::class, $classes, true);

        // An identified principal with unqualified view sees everything; no scoping.
        if ($user !== null && $this->permits($user, PermissionNamer::assemble($modelClass, 'view'))) {
            return $query;
        }

        $instance = new $modelClass;
        $table = $instance->getTable();
        $reach = app(ReachResolver::class);
        $tiers = $reach->listableTiers($user);
        $listedColumn = $hasVisibility ? $instance->visibilityListedColumn() : null;

        // The tier-visible sub-query: reach-listable tiers, narrowed to `listed` rows when
        // the model has a discoverability axis. Empty tier set → matches nothing.
        $tierBranch = function ($q) use ($table, $tiers, $listedColumn) {
            if ($tiers === []) {
                $q->whereRaw('1 = 0');

                return;
            }
            $q->whereIn("{$table}.visibility", $tiers);
            if ($listedColumn !== null) {
                $q->where("{$table}.{$listedColumn}", true);
            }
        };

        // Legacy path: models without the directory ACL keep own-only scoping — and a guest
        // sees nothing, since there is no reach axis to widen to.
        if (! $hasVisibility) {
            if ($user === null) {
                return $query->whereRaw('1 = 0');
            }
            if ($this->permits($user, PermissionNamer::assemble($modelClass, 'own', 'view'))) {
                if (in_array(HasUserId::class, $classes)) {
                    return $query->where('user_id', $user->id);
                } elseif (in_array(HasUser::class, $classes)) {
                    return $query->whereHas('user', fn ($q) => $q->where('user_id', $user->id));
                }
            }

            return $query->whereRaw('1 = 0');
        }

        // Anonymous viewer on a directory-ACL model: only the reach-listable tiers (no own,
        // no grants — a guest holds neither).
        if ($user === null) {
            return $query->where($tierBranch);
        }

        // Directory-ACL path: own ∪ (tier-visible ∪ direct allow-grants) − direct deny-grants.
        // Steward (own) is non-deniable, so denies subtract only from the shared branch.
        $morph = $instance->getMorphClass();
        $ownsPermitted = $this->permits($user, PermissionNamer::assemble($modelClass, 'own', 'view'));
        $allowedIds = $this->grantedGrantableIds($morph, $user, Grant::EFFECT_ALLOW);
        $deniedIds = $this->grantedGrantableIds($morph, $user, Grant::EFFECT_DENY);

        return $query->where(function ($outer) use ($table, $classes, $ownsPermitted, $user, $allowedIds, $deniedIds, $tierBranch) {
            $shared = function ($q) use ($table, $allowedIds, $deniedIds, $tierBranch) {
                $q->where(function ($tierOrGrant) use ($table, $allowedIds, $tierBranch) {
                    // Tier-visible branch (listed only, when the model has a listed axis)…
                    $tierOrGrant->where($tierBranch);
                    // …or a direct allow-grant, which lists regardless of tier/listed.
                    if ($allowedIds !== []) {
                        $tierOrGrant->orWhereIn("{$table}.id", $allowedIds);
                    }
                });
                if ($deniedIds !== []) {
                    $q->whereNotIn("{$table}.id", $deniedIds);
                }
            };

            if ($ownsPermitted) {
                $outer->where(function ($own) use ($table, $classes, $user) {
                    if (in_array(HasUserId::class, $classes)) {
                        $own->where("{$table}.user_id", $user->id);
                    } elseif (in_array(HasUser::class, $classes)) {
                        $own->whereHas('user', fn ($qq) => $qq->where('user_id', $user->id));
                    } else {
                        $own->whereRaw('1 = 0');
                    }
                })->orWhere($shared);
            } else {
                $outer->where($shared);
            }
        });
    }

    public function viewAny(Authenticatable $user)
    {
        return $this->permits($user, PermissionNamer::assemble(static::$defaultModelClass, 'view'))
            || $this->permits($user, PermissionNamer::assemble(static::$defaultModelClass, 'own', 'view'));
    }

    public function view(?Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'view');
    }

    public function create(Authenticatable $user)
    {
        return $this->permits($user, PermissionNamer::assemble(static::$defaultModelClass, 'create'));
    }

    public function update(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'update');
    }

    public function delete(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'delete');
    }

    public function restore(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'restore');
    }

    public function forceDelete(Authenticatable $user, Model $instance)
    {
        return $this->canCascade($user, $instance, 'force-delete');
    }
}
