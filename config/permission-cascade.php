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
];
