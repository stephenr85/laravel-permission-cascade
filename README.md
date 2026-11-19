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

A policy class that implements `Contracts\GrantedExplicitly` marks its tokens as reserved. A
consumer that derives role grants from the Gate's policy map (for example, beam-accounts'
`RolePermissions`) must skip that model, so only a grant that names it explicitly can hand out its
tokens. With no such grant, the host's `Gate::before` superuser is the only principal that passes.

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

## A scoped credential fails closed

A host binds a `CredentialScopeResolver` (beam-accounts binds one from the acting Sanctum token's abilities) and
registers `Authorization\CredentialScopeGate::before()` as its first `Gate::before` (beam does this for every beam
host). Then, for the request's authenticated principal acting with a scoped credential, **every** Gate decision is
"the principal may AND the token carries the decision's name" (fleet ADR 0006, `rushing/splicewire-beam-runbook`
`docs/adr/0006-a-credential-scope-fails-closed-and-machine-tokens-are-never-unscoped.md`, amending the flagship's
ADR-0109). A decision's name is, first match wins:

1. a flat permission name (`declarations.check`, `tenant:provision`): itself;
2. a name registered in `Authorization\DecisionNames` (`->name('reviewMarketListing', 'reviewMarketListing')`, per
   subject class or for every subject) or listed in `config('permission-cascade.decision_names')`;
3. the names the subject's policy declares through `Contracts\NamesDecisions` (`BaseModelPolicy` names every rung:
   `{model}.{action}`, `{model}.{id}.{action}`, `{model}.own.{action}`, `{model}.shared.{action}`; `viewAny` lists
   by `view`; only while the cascade's own verb method and rung machinery run: a verb a subclass overrides, or a
   `ConfiguredModelPolicy` verb answered by an override, falls through to the derivation);
4. the derivation for a verb on a model subject: `{model}.{verb}` and `{model}.{id}.{verb}` (the verb as written and
   kebab-cased). Membership, ownership, participant and seller arms are named this way: they are policy verbs.

A decision with no name (a subjectless `Gate::define` nobody registered, a policy over a subject that is no model) is
refused with code `credential_scope_unnamed_decision`; a name the token lacks with `credential_scope_name_not_carried`.
Both are a 403 (`Authorization\CredentialScopeRefused`, rendering `{message, code}` as JSON); `Gate::allows()` answers
false. Inside `BaseModelPolicy` the rungs that ask no permission (the steward, the morph owner, explicit grants, the
reach tier) answer a scoped credential only when it carries the action's or the rung's name. The listing scope
(`scopeForUser()`) is a query scope, not a Gate decision, and is not narrowed yet.

Unchanged: a session, a `*` token, a guest, a check for another principal, and the entitlement plane
(`entitlement:{key}`), which is answered principal-only, permissions its definition asks included. A host's allow-all
before (a Root) answers through `CredentialScopeGate::superuser()`, and a Root arm inside a policy through
`superuserMay()`: under a scope a superuser grant holds only for a name the token carries.

## Config

See `config/permission-cascade.php`: `reach_resolver`, `credential_scope_resolver`, `decision_names`,
`platform_admin_permission`, `team_foreign_key`, `manage_spatie_teams`, `user_model`.

## Testing

```
composer test   # pest
composer pint   # style
```
