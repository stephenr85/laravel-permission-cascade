<?php

namespace Rushing\PermissionCascade;

use Illuminate\Support\ServiceProvider;
use Rushing\PermissionCascade\Support\PermissionNamer;

class PermissionCascadeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/permission-cascade.php', 'permission-cascade');

        $this->app->singleton(PermissionNamer::class, fn () => new PermissionNamer);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/permission-cascade.php' => $this->app->configPath('permission-cascade.php'),
            ], 'permission-cascade-config');
        }

        $this->configureSpatieTeams();
    }

    /**
     * The cascade is teams-first. Unless the host opts out, force spatie into
     * teams-mode with the configured foreign key (the tenancy-agnostic seam:
     * 'team_id' on a satellite, 'tenant_id' on the platform).
     */
    protected function configureSpatieTeams(): void
    {
        if (! config('permission-cascade.manage_spatie_teams', true)) {
            return;
        }

        // spatie reads the key from column_names.team_foreign_key (the registrar's
        // teamsKey and the migration both use it) — not a top-level permission key.
        config([
            'permission.teams' => true,
            'permission.column_names.team_foreign_key' => config('permission-cascade.team_foreign_key', 'team_id'),
        ]);
    }
}
