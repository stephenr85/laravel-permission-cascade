<?php

namespace Rushing\PermissionCascade;

use Illuminate\Support\ServiceProvider;
use Rushing\PermissionCascade\Contracts\CredentialScopeResolver;
use Rushing\PermissionCascade\Contracts\EntitlementResolver;
use Rushing\PermissionCascade\Contracts\ReachResolver;
use Rushing\PermissionCascade\Support\DefaultReachResolver;
use Rushing\PermissionCascade\Support\NullCredentialScopeResolver;
use Rushing\PermissionCascade\Support\NullEntitlementResolver;
use Rushing\PermissionCascade\Support\PermissionNamer;

class PermissionCascadeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/permission-cascade.php', 'permission-cascade');

        $this->app->singleton(PermissionNamer::class, fn () => new PermissionNamer);

        // The credential-scope seam. Defaults to unscoped (NullCredentialScopeResolver),
        // so authorization is unchanged until a host binds a narrowing resolver — either
        // by pointing config('permission-cascade.credential_scope_resolver') at a class or
        // closure, or by rebinding this contract directly (e.g. an accounts package that
        // sources the scope from an acting API token). The cascade never learns what the
        // credential mechanism is; it only consults permission-names.
        $this->app->singleton(CredentialScopeResolver::class, function ($app) {
            $resolver = config('permission-cascade.credential_scope_resolver');

            if ($resolver === null) {
                return new NullCredentialScopeResolver;
            }

            return is_callable($resolver) ? $resolver($app) : $app->make($resolver);
        });

        // The reach seam (see Contracts\ReachResolver). Defaults to DefaultReachResolver,
        // which reproduces the historical tenant/platform vocabulary with no anonymous
        // reach — so authorization is unchanged until a host binds a resolver that adds
        // tiers (e.g. a public-to-anonymous tier). A host points
        // config('permission-cascade.reach_resolver') at a class or closure, or rebinds
        // this contract directly.
        $this->app->singleton(ReachResolver::class, function ($app) {
            $resolver = config('permission-cascade.reach_resolver');

            if ($resolver === null) {
                return new DefaultReachResolver;
            }

            return is_callable($resolver) ? $resolver($app) : $app->make($resolver);
        });

        // The entitlement seam (see Contracts\EntitlementResolver) — the feature-access axis,
        // distinct from the per-action cascade. null → NullEntitlementResolver: every principal
        // holds the empty set, so an unbound host is entitled to nothing and behaviour is
        // unchanged (the DefaultReachResolver discipline, ADR-0009). Point this at a class-string
        // or a closure returning an EntitlementResolver to map a plan/grant model to a flat set of
        // entitlement keys (plan-baseline ∪ grants − denies). beam is the authority that binds the
        // concrete resolver + registers entitlement gate abilities (Frame OS ADR-0013). Hosts may
        // instead rebind the contract in the container directly.
        $this->app->singleton(EntitlementResolver::class, function ($app) {
            $resolver = config('permission-cascade.entitlement_resolver');

            if ($resolver === null) {
                return new NullEntitlementResolver;
            }

            return is_callable($resolver) ? $resolver($app) : $app->make($resolver);
        });
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
