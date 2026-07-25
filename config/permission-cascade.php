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

    // The credential-scope seam (see Contracts\CredentialScopeResolver). null → unscoped:
    // authorization is exactly the principal's. Point this at a class-string or a closure
    // returning a CredentialScopeResolver to narrow authority by the acting credential's
    // scope (effective authority = principal permissions ∩ credential-scope). Narrow-only:
    // it can subtract a granted permission, never grant one the principal lacks. Hosts may
    // instead rebind the contract in the container directly.
    'credential_scope_resolver' => null,
];
