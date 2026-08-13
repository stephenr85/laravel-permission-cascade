<?php

return [
    // The Authenticatable model the ownership traits (HasUser/HasUserId) resolve to.
    // null falls back to the default auth provider model. May be a class-string or a
    // closure returning one, e.g. to switch on tenancy state:
    //   'user_model' => fn () => tenancy()->initialized ? TenantUser::class : User::class,
    'user_model' => null,

    // spatie teams-mode foreign key. 'team_id' is the satellite default; a host with a
    // different tenancy column (e.g. 'tenant_id' on the platform) overrides this.
    'team_foreign_key' => 'team_id',

    // When true, the provider forces spatie into teams-mode using team_foreign_key.
    // Set false if the host manages spatie's teams config itself.
    'manage_spatie_teams' => true,

    // The permission token the directory-ACL `.shared.` rung reads to gate *manage* on a
    // `platform`-tier object (view on a platform object is open to any member; manage is not).
    // A host that seeds a different platform-admin token overrides this. See ADR directory-ACL.
    'platform_admin_permission' => 'platform.manage',

    // The host's grant model — an Eloquent model implementing Contracts\AccessGrant (grantable +
    // grantee morphs, `ability`/`effect`). The package is model-free: it ships the contract
    // and the resolution logic, not a model, so the host owns the table name, casts, and any
    // extra columns. null → explicit grants are not wired; authorization uses steward + reach
    // tier only (the base cascade still works). Example: App\Models\AccessGrant::class.
    'grant_model' => null,

    // The visibility seam — an Eloquent model implementing Contracts\VisibilityRecord (a
    // `reachable` morph + `tier`, optionally `listed`). The package is model-free here too: it
    // ships the contract and the resolution logic, not a model, so the host owns the table and
    // columns. null → HasVisibility falls back to its original column-based behavior (a
    // `visibility` column on the policied model's own table) — fully backward compatible. Set
    // this when a host would rather not add a visibility/listed column to every policied
    // model's own table. Example: App\Models\VisibilityRecord::class.
    'visibility_model' => null,

    // The reach seam (see Contracts\ReachResolver) — the audience-breadth axis of
    // visibility. null → DefaultReachResolver: the historical `tenant`/`platform`
    // vocabulary with no anonymous reach, so behaviour is unchanged. Point this at a
    // class-string or a closure returning a ReachResolver to add tiers — e.g. a `public`
    // tier that widens to an anonymous (guest) viewer, or to drive the listable-tier set.
    // Hosts may instead rebind the contract in the container directly.
    'reach_resolver' => null,

    // The credential-scope seam (see Contracts\CredentialScopeResolver). null → unscoped:
    // authorization is exactly the principal's. Point this at a class-string or a closure
    // returning a CredentialScopeResolver to narrow authority by the acting credential's
    // scope (effective authority = principal permissions ∩ credential-scope). Narrow-only:
    // it can subtract a granted permission, never grant one the principal lacks. Hosts may
    // instead rebind the contract in the container directly.
    'credential_scope_resolver' => null,

    // The entitlement seam (see Contracts\EntitlementResolver) — the feature-access axis,
    // orthogonal to the per-action cascade and to reach. null → NullEntitlementResolver: every
    // principal holds the empty set, so an unbound host is entitled to nothing and behaviour is
    // unchanged. Point this at a class-string or a closure returning an EntitlementResolver to map
    // a plan/grant model to a flat set of entitlement keys (plan-baseline ∪ grants − denies). beam
    // is the authority that binds the concrete resolver and registers entitlement gate abilities
    // (Frame OS ADR-0013). Hosts may instead rebind the contract in the container directly.
    'entitlement_resolver' => null,
];
