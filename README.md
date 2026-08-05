# laravel-permission-cascade

Host-agnostic authorization cascade for Laravel: model-scoped permission naming, a base
policy that resolves `Model.action → Model.{id}.action → Model.own.action` ownership, a
directory-style ACL (deny-capable grants + a visibility model), and spatie teams-mode
conventions with a configurable team foreign key.

## The authorization cascade

`BaseModelPolicy` resolves an ability through four rungs, first match wins:

1. **Class** — `Model.action` (e.g. `composition.update`).
2. **Instance** — `Model.{id}.action`.
3. **Steward / owner** — `Model.own.action` for the record's `HasUser`/`HasUserId` owner.
4. **Shared ACL** (`.shared.` rung, models using `HasVisibility`) — explicit deny-capable
   grants, then the reach tier. Purely additive: it only grants access the token rungs
   didn't, and never revokes a steward/token above it (anti-lockout).

`scopeForUser($query, $user)` is the listing counterpart of rung 4: `own ∪ (reach-listable
tiers ∪ direct allow-grants) − direct deny-grants`.

## Visibility: two orthogonal axes

Visibility is **not** a single ladder. `HasVisibility` models two independent axes plus the
grant ledger:

### Reach — *how broad is the audience?*

The `visibility` column is a **host-defined tier string**. Its meaning comes from a bound
`Contracts\ReachResolver` — the one place a tier is interpreted; the cascade never hardcodes
a vocabulary. The shipped `Support\DefaultReachResolver` reproduces the historical semantics:

- `platform` — any authenticated member views; *manage* gated on the platform-admin token.
- `tenant` — any authenticated member views; manage stays steward + grant.
- `private`/NULL/unknown — steward + grants only.
- **no anonymous reach** — an unauthenticated viewer widens nothing.

A host adds tiers by binding its own resolver (`config('permission-cascade.reach_resolver')`
or rebinding the contract). Example — a `public` tier reachable by the anonymous viewer:

```php
class PublicReachResolver implements ReachResolver
{
    public function grants(?string $tier, string $ability, ?Authenticatable $viewer): bool
    {
        return $ability === 'view' && in_array($tier, ['public', 'unlisted'], true);
    }

    public function listableTiers(?Authenticatable $viewer): array
    {
        return ['public']; // `unlisted` is viewable per-record but never in a feed
    }
}
```

The **anonymous path** is first-class: `view(null, $model)` and `scopeForUser($query, null)`
resolve through the resolver's guest branch. The default resolver grants a guest nothing, so
anonymous access is strictly opt-in.

### Discoverability — *listed in feeds, or link-only?*

Orthogonal to reach. A model opts in by overriding `visibilityListedColumn()` to name a
boolean column; `scopeForUser` then narrows the *tier* branch to `listed` rows, while the
per-record `view()` ignores it. A tier that grants a per-record view yet is absent from
`listableTiers()` — or a `listed = false` row — is exactly *"reachable by anyone, but not in
the feed."* Off by default (no listed column ⇒ every row is listed).

### Principals — *these specific people/teams*

Deny-capable `Grant` rows (grantable morph → grantee user/role, ability `view|manage`, effect
`allow|deny`; nearest-wins, deny beats allow, `manage ⊇ view`). Orthogonal to both axes.

## Config

See `config/permission-cascade.php`: `reach_resolver`, `credential_scope_resolver`,
`platform_admin_permission`, `team_foreign_key`, `manage_spatie_teams`, `user_model`.

## Testing

```
composer test   # pest
composer pint   # style
```
