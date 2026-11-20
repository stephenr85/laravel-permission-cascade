# Credential-scope decision inventory

The fleet record that fleet ADR 0006 C2 asks for (`rushing/splicewire-beam-runbook`
`docs/adr/0006-a-credential-scope-fails-closed-and-machine-tokens-are-never-unscoped.md`): every authorization
decision a token call can reach, in a policy, a Gate definition, a `before`, or a controller, middleware or query
scope that checks a role, membership or ownership inline, with the name a scoped token must carry to pass it.
Written by credential-scope 05 (map `.scratch/rushing/laravel-permission-cascade/credential-scope/` in the ecosystem
workspace); the enforcement is `Authorization\CredentialScopeGate` (02).

## How a decision gets its name

| where the decision is made | its name under a scoped token | mechanism |
|---|---|---|
| a flat ability (`declarations.check`, `tenant:provision`, `agreement:x`) | itself | `CredentialScopeGate::isPermissionName()` |
| a subjectless or non-model Gate ability | the name its owner registers | `DecisionNames::name()`, `config('permission-cascade.decision_names')` |
| a policy verb on a model (membership, ownership, participant, seller arms included) | `{model}.{verb}`, `{model}.{id}.{verb}`; a `NamesDecisions` policy adds its own | derivation; `BaseModelPolicy` adds `.own.` / `.shared.` rungs, and a subclass that overrides a verb but still runs the rungs returns `cascadeRungNames()` (05) |
| a Root arm inside a policy or a host `before` | the strict name (registered or derived) | `superuser()`, `superuserMay()` |
| a listing's row scope | `{model}.view`, plus `{model}.own.view` (owner rows) / `{model}.shared.view` (tier and grant rows) | `BaseModelPolicy::scopeForUser()` (05) |
| a check outside the Gate | the name the call site passes, or the one registered under the decision's key | `carries()`, `authorizeCarried()` (05) |
| `entitlement:{key}` | exempt (principal-only, C4) | `CredentialScopeGate::principalOnly()` |

A decision that resolves to no name refuses a scoped token (`credential_scope_unnamed_decision`); that is the
fail-closed answer, not a gap, for a decision no token should make (`viewHorizon`, `bypass-marquee`). A gap is a
decision that a scoped token passes **without** being asked for a name: those are the rows marked **open** below.

## Probes (two shapes, per AGENTS.md "Counts")

Scope: the 121 PHP repositories in `pnpm whiffletree repos` (registry rows with a `composer.json`), scanned at the
shas in the evidence file `scan-roots.tsv`: the space `cs05` worktrees (origin/main on 2026-11-20) for cascade, beam,
beam-accounts, beam-market, tower and the flagship, the live checkout otherwise. Of the 115 live checkouts, 99 equal
their `origin/main`, 2 have no remote, and 14 are behind it (`live-vs-origin.tsv`); for 10 of those 14 the
`live..origin` PHP diff (read from whiffletree's mirrors) adds no line matching any probe (`probeG-origin-delta.txt`),
and the other 4 (`laravel-beam-exec`, `laravel-composition-spine`, `laravel-satellite-composition`,
`calcucrypt-tutorial`), which no mirror held at both shas, were scanned at their exact origin revisions (probe L
below). `vendor*`, `tests`, `database`, `.compat` excluded. Evidence:
`~/Workspaces/tmp/evidence/credential-scope/logs/05/inventory/`.

- **A, file shape:** every `*Policy.php` (104 files in 37 repos; the domain "policy" objects among them are listed
  below as no-decision).
- **B, registration shape:** `Gate::define|before|after|policy`, `$gate->define|before`, `function before(`,
  `#[UsePolicy]`, `$policies`, `NamesDecisions`, `DecisionNames::` (159 code lines).
- **C, D, E, inline shapes:** `->hasRole|hasAnyRole|isRoot|isAdmin|hasTeamRole|belongsToTeam|activeTenants|isOwnedBy|
  hasPermissionTo(` (49 lines); `::isRoot(`, `role:` middleware, `->user_id|owner_id|created_by ===` comparisons,
  `getAuthIdentifier() ===` (78 lines); `->is($request->user())`, `abort_*` with an ownership or role read (2 lines).
- **F, read-policy shape:** `implements ResourceReadPolicy` (19 classes): beam's particle read decision, asked by
  `ResourceReadGuard` **outside** the Gate.
- **Runtime census (a differently-shaped second probe):** the flagship booted in its test environment, every
  `Gate::abilities()` key and `Gate::policies()` binding passed through `CredentialScopeGate::namesFor()`
  (`census-flagship.tsv`, 113 rows). It agrees with B: every non-entitlement ability is self-named or derives a name
  once its subject is passed, except `viewHorizon` (web-only) and `manageMembers` / `manageInvitations` /
  `manageInvitation` when asked with no subject (every call site passes a team or invitation, so they derive).

## Inventory by repository

Status: **named** (a scoped token passes only with the name), **fail-closed** (no name; a scoped token is refused,
correctly), **exempt** (ADR 0006's exemptions), **open** (a scoped token passes without a name: remainder),
**not reachable** (no token call reaches it), **out of scope** (by ruling).

### rushing/laravel-permission-cascade

| decision | name | status |
|---|---|---|
| `BaseModelPolicy` verbs and rungs (class, instance, steward / morph owner, grants / tier) | `{m}.{a}`, `{m}.{id}.{a}`, `{m}.own.{a}`, `{m}.shared.{a}` | named (02) |
| `ConfiguredModelPolicy` (every `#[UseCascadePolicy]` model) and overriding subclasses | derived; rung names only while the cascade's rungs run | named (02) |
| `BaseModelPolicy::scopeForUser()` row scope | `{m}.view` + `.own.view` / `.shared.view` | named (05) |

### splicewire/laravel-beam

| decision | name | status |
|---|---|---|
| `SavedFilterPolicy`, `BeamSchemaPolicy`, `GitRepoPolicy` | derived (`saved-filter.*`, `beam-schema.*`, `git-repo.*`) | named |
| `beam.actor-owned-particle.write`, `beam.config-section.read/operate` | themselves | named |
| `CredentialScopeGate` registration, entitlement `before` | — | enforcement / exempt |
| `ModelOrOperatorReadPolicy`, `GitRepoReadPolicy`, `RealmEntitlementReadPolicy` (read policies) | Gate `viewAny` (derived) or the entitlement plane | named / exempt |
| `AuthenticatedReadPolicy`, `ActorOwnedParticleAccess` / `SharedParticleAccess` read arms, and `ResourceReadGuard`'s admissions by a tenancy or declared row scope with no policy, a policy without `viewAny`, a realm entitlement or an `entitlement:` read gate; a relative-mount list | `{key}.view` or `{model}.view` (`ResourceReadGuard::readNames()`); every resource's `{key}.view` offered | named (07 R1, beam 651dca1) |
| `SavedFilterService:108` owner compare (a restriction beside the Gate's `update` / `delete` on the saved filter) | `saved-filter.*` | named |
| deprecated `Splicewire\Beam\Authorization\CredentialScopeGate` alias | — | removed (05) |
| `Filters\SavedFilterResourceHandler` `visible()` / `find()` (`:14`, `:25`; `SavedFilterService:35,45` own-or-shared predicate), a custom Frame handler that `FrameResourceController` dispatches with no read question | `saved-filters.view`, `saved-filter.view`, `saved-filter.{id}.view` (target resource and ownership restrictions kept) | named (07 R5, beam 651dca1) |

### splicewire/laravel-beam-accounts

| decision | name | status |
|---|---|---|
| `UserPolicy` (self arm, Root arm) | `user.{verb}`, `user.{id}.{verb}` | named (02, #39) |
| `InvitationPolicy`, team-role fallback | `invitation.*` | named (#39) |
| `TokenPolicy` | `personal-access-token.*` | named |
| `MembershipPolicy` via `manageMembers` / `manageInvitations` / `manageInvitation` (always asked with a team / invitation) | `{team-model}.manage-members`, `.manage-invitations`, `invitation.manage-invitation` (+ `{id}`) | named (derived) |
| `ux.author`, `ux.{realm}.author`, `request-{key}-access` (on a model) | themselves / derived | named |
| `TeamMemberReadPolicy` (member arm), `InvitationReadPolicy` (read policies); `MePolicy` (declared, but `GET /me` bypasses it: R5) | the resource's `{key}.view` / `{model}.view` | named (07 R1, in beam's guard, beam 651dca1) |
| `PasskeyController` (every verb: list, registration options and register, rename, revoke; owner `abort_unless` stays the principal half) | `passkey.{verb}`, `passkey.{id}.{verb}` (offered) | named (07 R2, beam-accounts 3970972) |
| `Api\V1\ProfileController::update` (`PATCH /me`, self-service name / email write) | `user.update`, `user.{id}.update` (as `UserPolicy::update`'s self arm) | named (05 review, beam-accounts 4806773) |
| `Api\V1\MeController::show` (`GET /me`): projects `request()->user()` directly through `ParticleController::respond()` (beam `ParticleController.php:883`), never reaching `ResourceReadGuard` or `MePolicy` | `me.view`, or the configured user model's `user.view` / `user.{id}.view` | named (07 R5, beam-accounts 3970972) |
| `UsersQuery:42` Root reads every user (a row scope) | `superuserMay(viewAny, user)`: `user.view`; otherwise the shared-teams scope | named (07 R2, beam-accounts 3970972) |
| `Account\TeamMemberController` membership and owner reads (`index`, `roles`, `updateRole`, `remove`: `NotTeamMember`, `TeamOwnerRequired`) and `TeamMembers:73,98` | `viewMembers` (`{team}.view-members`) for the reads, `manageMembers` (`{team}.manage-members`) for the owner writes, in the controller and in `TeamMembers::assertOwner` (offered) | named (07 R2, beam-accounts 3970972) |
| `ImpersonateUser:66` self refusal (a refusal, inside an op with `ability:`) | the op's | named |

### splicewire/laravel-beam-market

| decision | name | status |
|---|---|---|
| `SellerRepoAuthorizationPolicy` | `seller-repo-authorization.*` | named |
| `reviewMarketListing` (Root-only define) | `reviewMarketListing` (registered) | named (02) |
| `TenantReportingSite:42` membership read for heartbeat / uninstall | `installed-extensions.report` (offered, so the device-flow widest token carries it; 06 proves the consumer) | named (07 R2, beam-market ee4a3fe) |
| `MarketProductRowScope:113` Root sees every product (row scope) | `superuserMay(viewAny, market-product)`; otherwise the actor's Seller | named (07 R2, beam-market ee4a3fe) |
| `PricingPolicy`, `ComposerInstallPolicy`; workflow `role:` await principals | — | no decision (domain objects, await routing) |

### other splicewire/laravel-beam-* packages and satellite packages

| repo | decisions | status |
|---|---|---|
| beam-agreements | `agreement:{key}` `before` | named (flat) |
| beam-analytics | `analytics-area.view.*` | named (flat) |
| beam-calendars | `ActionPolicy`, `ActionSeriesPolicy`, cascade models | named (derived) |
| beam-commerce | `PlanPolicy`, `SiteBillingEntryPolicy`; `entitlement:commerce.manage` | named / exempt |
| beam-docs | `PublicationPolicy`, `ProsePolicy` | no decision (domain objects) |
| beam-embed | `EmbedPolicy` | named (rungs) |
| beam-media | `media.ingest` | named (flat) |
| beam-notifications | ledger model cascade policy | named (rungs) |
| beam-rank | `RankData:42` (presentation) | no decision |
| beam-tenancy | `WorkspaceSeats` (seat count), `TenantAnalyticsEntitlement` (entitlement), seeders, testing helpers | no decision / exempt / not reachable |
| beam-ux | `ReleasePolicy`, `RedirectPolicy`, `BeamUxEntryPolicy`; `beam-ux.*`, `realm-dashboard.view.*`, `section-overview.view.*` | named |
| beam-ux | `DiagnosticsReadPolicy`, `FilesRecordingReadPolicy` (read policies, each asks a Gate ability) | named |
| beam-ux | `TokenAccessGate:108`: an entry's `root` access token is a Root role read (its `<alias>.<verb>` tokens ask `can()` and are named) | named (07 R2, beam-ux 6e40fe8): `superuserMay(right, entry)`, `beam-ux-entry.{right}` (offered) |
| satellite-knowledge | `FragmentUrlBatchPolicy`, `FragmentConceptAnchorPolicy`; `ChunkPolicy` (domain) | named / no decision |
| beam-extension-demo | `DemoNotePolicy` | named (derived) |

### splicewire/tower

| decision | name | status |
|---|---|---|
| model policies (`Entity`, `Thread`, `ModelStatus`, `Message`, `TenantSync`, `Rule`, `EntitySectionRevision`, `EntityEvidenceItem`, `EntityObligation`, `EntityRegistration`, `EntityAssessment`, `Conduit`) | derived / declared | named (02) |
| `ConduitPolicy::before` Root arm | `conduit.{verb}` | named (#39); imports the cascade class (05) |
| `ThreadPolicy::scopeForUser()` (a copy of the parent's) | `thread.view` / `thread.own.view` / `thread.shared.view` | named (05) |
| `ThreadPolicy::view` / `update`, `EntityPolicy::update` (override a verb, then run the rungs; Entity adds a steward arm) | every rung name, declared through `cascadeRungNames()`; the steward arm by `.update` / `.own.update` | named (05) |
| flat defines (`embeddings.embed`, `connected-sites.revoke`, `operator-connected-sites.revoke`, `entity-evidence.write`, `entity-obligations.record-receipt`, `disclosures.record`, `activity.resource.read`) | themselves | named |
| `intake` (asked with a circuit) | `circuit.intake`, `circuit.{id}.intake` | named (derived) |
| `TenantSyncController` central Root arm (was `:78`) | `tenants.sync` | named (05) |
| `KnowledgeGraphController` corpus re-anchor (was `:381`, Admin/Root read) | `concept.update` | named (05) |
| `TenantIndexController` seats list (`activeTenants()`) | `tenant.view` | named (05) |
| `TenantMemberReadPolicy` member arm; machine arm | `{key}.view` | named (05; machine arm #36) |
| `OperatorResourceReadPolicy`, `ScaffoldPackReadPolicy` | Gate `viewAny` / entitlement / `scaffold-pack.*` | named / exempt |
| `ProvisionTenantInputData:82` Root may name a parent (a field rule on `provision.tenant` routes) | `tenant:provision` (the route's) | named |
| `ReviewInbox:194` awaiting rows by the user's role tokens | inside a named read: reached only through `review-queue` / `review-units` (`TenantMemberReadPolicy`, `{key}.view`, 05) and their `review_parents` options (after the parent's read) | named (07 R2: classified, no change) |
| filter options sources `AgentOptionsSource:18`, `CircuitOptionsSource:18` (owner-filtered by `user_id`), `SiloOptionsSource`, `TagOptionsSource`: returned by `ResourceFilters:123` after only the parent resource is authorized (`:99`) | intended: the related model's `agent.view` / `agent.own.view`, `circuit.view` / `circuit.own.view`, `silo.view`, `tag.view` (owner filter kept), registered under `filter-options:{ref}` and asked by beam `ResourceFilters::options()` | named (07 R5, tower c4138d4 + beam 651dca1) |
| `Frame\ConduitResourceHandler` index, show, summary (custom Frame handler); update asks its response's read before the first write | `conduits.view`, `conduit.view`, `conduit.{id}.view` via `ResourceReadGuard::authorizeScopedRead()` | named (07 R5, tower c4138d4; update order a8407cd) |
| `Api\V1\ThreadController@create` / `@update` (a thread named by a body or route `id`, saved with no decision: any member rewrote any thread; found by R6) | `thread.update`, `thread.{id}.update`, `thread.own.update` (ThreadPolicy::update, asked before any write) | named (07, orchestrator ruling, tower f9dd5e7) |
| `Navigation\Gates\AccessGate:65` Root nav token | an offer, not an authority | not reachable as a grant |
| `PolishPolicy`, `MaterializationPolicy`, federation `*ResolutionPolicy` / `CorpusAudiencePolicy` | — | no decision (domain objects) |

### splicewire/splicewire-app (the flagship)

| decision | name | status |
|---|---|---|
| `RunnerTransformPolicy` (Root arm) | `runner-transform.*` | named (#39) |
| Root `Gate::before`; `ux.author` / manifest `viewAny` / records befores through `site.edit` | `superuser()`; the outer name, then `site.edit` | named (#39, 02) |
| `entitlement:os.operate`, `exec.view`, `analytics.view` definitions | — | exempt (C4); the doors are named (Q1 below; an `entitlement:` particle read gate asks `{key}.view`, R1) |
| `analytics.destination.*`, `activity.resource.read` | themselves | named |
| `HopController::issue` | refused for any scoped token | named (02, C9) |
| `RequireAdminRole` (`require.admin`) and `RoleReachabilityProbe` admin arm | `tenant.administer` (registered under `require.admin`) | named (05) |
| `AuthorizeTenantProvisioning` Root arm | `tenant:provision` | named (05) |
| `ChooserController` (the reader's own record) | `user.view`, `user.{id}.view` (routed through `UserPolicy::view`) | named (05) |
| `RoleReachabilityProbe` root arm | `entitlement:os.operate` and `operator.access`, as `RequireRootRole` | named (07 Q1, app 2efe426) |
| `RequireRootRole` (`require.root` → `entitlement:os.operate`, defined as `isRoot`) | `operator.access` (registered under `require.root`); the entitlement stays principal-only | named (07 Q1, app 2efe426) |
| `WorkflowExecutionAuthority:56` membership read | a refusal-only check before `Gate::forUser($principal)->authorize($ability, $subject)` (`update` / `site.edit`, narrowed); it can refuse, never admit | named (07 R2: classified, no change) |
| `viewHorizon` (web guard) | — | fail-closed; not reachable by a bearer |
| `HostTenant`, `TenantLandingSeats`, `routes/web.php:116` membership reads | — | not reachable (session landing) |
| `EngineConsumerToken:143` Admin read | — | a mint site: ticket 04 |
| `Dev\SubstrateChatController` `create` / `update` | — | not reachable (dev only) |

### Sites and starters

| repo | decisions | status |
|---|---|---|
| rushing/standwell | `Gate::define`d `documents.*`, `exposures.remediate`, `assessments.scan`, `packet-shares.view`, `source-connections.*`, `agreement-values.dispute`, `received-packets.view`, … (membership / owner role inside: the principal half) | named (flat) |
| rushing/standwell | `MerchantWorkspaceModelPolicy` | named (derived) |
| rushing/standwell | `MerchantWorkspaceReadPolicy`, `ReceivedPacketReadPolicy`, `ShareRecipientReadPolicy` (read policies) | named (07 R1, centrally in beam beam 651dca1) |
| rushing/standwell | `StandwellWorkflowActionAuthority:39` principal compare, then `Gate::authorize('view', $subject)` | named (derived) |
| rushing/standwell | `bypass-marquee` | fail-closed |
| rushing/entreport (held: read-only here) | `CompanyController:171` owner `abort_unless` (no policy, no Gate decision) | **open (R3)**: needs `company.view` / `company.{id}.view` (or a `CompanyPolicy` whose verbs derive them) |
| splicewire/audiostud | `RankPolicy`, `RankTreePolicy`, `SteeringProfilePolicy`; `ux.author`, realm author abilities; `create` / `update` on a `BeamParticle` | named |
| splicewire/audiostud | `AuthenticatedResourceReadPolicy`, `PublicResourceReadPolicy`, `OperatorResourceReadPolicy` | named (07 R1, in beam beam 651dca1); audiostud has no bearer route (R6) |
| splicewire/audiostud | ownership reads in `StudioController:391,475,493`, `SheetMusicController:59`, `SongController:101`, `ReportController:48`, ops `ChooseTake:21`, `ListTakes:21`, `TakeIteration:32-33`, `SubmitTimelineRegeneration:32-33` | not reachable by a bearer / named (07 R4, classified): the six controller reads are `routes/web.php` `auth` routes on the `web` session guard (`config/auth.php:19,41`; R6 found 0 bearer routes); the four ops are reached only through `#[ParticleOp(ability: 'view'|'update')]` on `Song` / `Project` (`ChooseTake`, `ListTakes`, `IterateTake`, `RegenerateTimeline`), a narrowed Gate decision; the owner compare is its principal half |
| splicewire/numero | `NumerologyResourcePolicy`, `VisibilityPolicy`; `bypass-marquee` | named / fail-closed |
| splicewire/numero | `SubjectAccess:96` owner read, `GrantController:55`, `Operator\EntitlementRefundController:42` | not reachable by a bearer (07 R4, classified): `routes/web.php:102` `auth` and `routes/operator.php:12` `auth` + `can:bypass-marquee` on the `web` session guard (`config/auth.php:19`); numero's bearer routes are its five `auth:api` numerology routes, each `ApiCaller::can` (R6) |
| splicewire/numero | `Frame\NumeroResourceHandler` (custom Frame handler, no read question) | not reachable by a bearer (07 R5, classified): numero's frame socket is `config/frame.php:47` `['web','auth','can:bypass-marquee']`, session only |
| splicewire/laravel-beam-commerce | `SiteBilling\Seat\BillingLedgerHandler` (custom Frame handler) | named (07 R5, beam-commerce f5cecb7): `{key}.view` via `ResourceReadGuard::authorizeScopedRead()` |
| stephenrushing (site) | `WorkspaceResourcePolicy::before` (site owner email), `bypass-marquee` | named (derived verbs) / fail-closed |
| calcucrypt, calcucrypt-tutorial | `CalculatorPolicy`, `PostPolicy`, `SavedInputPolicy`; `ux.author`, `beam-docs.publish` | named |
| starters (beam, satellite, commerce, market, tower) | `beam-docs.publish`, `ux.{realm}.author`, `site.edit`, `commerce.manage`, `market-extensions.install`, `installed-extensions.*`, `market-connections.sync` (Root or role inside: the principal half) | named (flat) |
| laravel-tower-starter example `ServiceRequestPolicy` | derived | named |
| thingsontv | `Role` middleware, `isAdmin()`, `viewHorizon` | not a beam-accounts host: no scope source is bound, so no token is scoped there (ADR 0006 rule 3 makes that a 04/06 question) |
| fable-legacy | its policies, `before`, 27 inline reads | out of scope (credential-scope 04 ruling: not a beam host) |
| rushing/* domain packages (`augmentation-loop`, `commerce`, `notification-status`, `postgres-rls`, `surgeon`), schemastud/*, conduit-ecfr, composition / knowledge spines, satellite-training | "Policy" domain objects only | no decision (probe A hits; B–F none) |

Every other registry PHP repo: no hit on any of probes A–F.

### Route-first and data-path sweep (review cs05)

The censuses above find decisions by how they are registered; the review showed code that bypasses both the Gate and
the read guard. Four more probes start from requests and data paths instead (evidence `logs/05/inventory/`):

- **H, route-first (flagship):** every route on the booted flagship whose middleware authenticates a bearer
  (`auth:sanctum`, 1135 routes: the flagship's own plus every tower, beam, beam-accounts and beam-market route it
  mounts), each controller method's own source read for an authorization step (`probeH-route-sweep-flagship.tsv`):
  392 gated in the method, 380 particle / Frame controllers (beam's generic read and op paths), 16 closures or
  invokables, **347 with no authorization step in the method**, 132 of them gated by a route middleware. The other 215
  are candidates, by controller: Splicewire\Beam\Webhooks\Http\HookEventCatalogController (68), Splicewire\Tower\Api\V1\KnowledgeGraphController (22), Splicewire\Tower\Api\V1\SystemModelsController (14), Splicewire\Tower\Composition\Http\Controllers\StudioController (12), Splicewire\Tower\Api\V1\EntityIntakeController (8), Splicewire\Tower\Api\V1\ApiTokenController (7), App\Http\Controllers\Api\V1\ContextScopeController (6), App\Http\Controllers\Api\V1\AgentController (6), Splicewire\Tower\Api\V1\SiloController (4), Splicewire\Tower\Api\V1\ModelStatusController (4), Splicewire\Tower\Api\V1\FragmentUrlBatchController (4), Splicewire\Tower\Api\V1\EmbeddingController (4), Splicewire\Tower\Api\V1\ConceptAnchorController (4), Splicewire\Beam\Market\Http\Controllers\Api\V1\ExtensionHeartbeatController (4), Splicewire\Beam\Commerce\Http\AutoReloadConfigController (4), Schemastud\Frame\Http\Controllers\FrameResourceFiltersController (4), App\Http\Controllers\Api\V1\CircuitController (4), Splicewire\Beam\Accounts\Http\Controllers\Api\V1\PasskeyController (3), Splicewire\Tower\Determination\Http\Controllers\DeterminationOverviewController (2), Splicewire\Tower\Api\V1\ThreadController (2), Splicewire\Tower\Api\V1\HybridSearchController (2), Splicewire\Tower\Api\V1\GuestTokenController (2), Splicewire\Tower\Api\V1\GraphOverviewController (2), Splicewire\Tower\Api\V1\GoldenSetController (2), Splicewire\Tower\Api\V1\FragmentController (2), Splicewire\Tower\Api\V1\EvalRunController (2), Splicewire\Tower\Api\V1\DereferenceController (2), Splicewire\Tower\Api\V1\CompletionController (2), Splicewire\Tower\Api\V1\BlockManifestController (2), Splicewire\Beam\Tenancy\Http\Controllers\TenantMemberController (2), Splicewire\Beam\Commerce\Http\Controllers\CreditsController (2), App\Http\Controllers\Api\V1\DeclarationController (2), Splicewire\Tower\Api\V1\TenantInvitationController (1), Splicewire\Tower\Api\V1\ReleaseController (1), Splicewire\Beam\Accounts\Http\Controllers\Api\V1\MeController (1), Splicewire\Beam\Accounts\Http\Controllers\Api\V1\LogoutController (1), Schemastud\Frame\Http\Controllers\FrameResourceSummaryController (1). Classified so far: `MeController::show` (R5), `PasskeyController` (R2),
  `TenantMemberController` (R2), the chooser and seats list (named, 05), `ApiTokenController` (ticket 04),
  `FrameResourceFiltersController` (the options sources, R5), `LogoutController` (revokes the caller's own token: no
  data), `HookEventCatalogController` (68 per-resource event-catalog reads: declared metadata, no records). **The rest
  are R6: to classify in ticket 07** (each either reaches a policy or row scope below the controller, or is a decision
  to name).
- **I, custom resource handlers** (`implements …ResourceHandler`, 7): beam `ParticleFrameResourceHandler` (asks
  `ResourceReadGuard`: R1 family) and `DefaultParticleResourceHandlerResolver`; `SavedFilterResourceHandler`, tower
  `ConduitResourceHandler`, numero `NumeroResourceHandler`, beam-commerce `BillingLedgerHandler` (no read question: R5);
  schemastud `BeamParticleResourceHandler` (abstract base).
- **J, options sources** (`implements OptionsSource`, 4 in tower): R5.
- **K, ownership queries** (`where('user_id'|'owner_id', <actor>)`, `whereBelongsTo(<actor>)`, `$request->user()->{relation}()->…`;
  151 lines, 88 of them fable-legacy, out of scope): declared Data `scope()` closures (satellite-training
  `TrainingRunData`, tower `ConnectedSiteData`, `ReleaseQuery`, `GuestLinkQuery`, calcucrypt-tutorial `SavedInputData`)
  are R1's row-scope admission; the cascade's own owner traits are the named rungs; the rest are rows above (R2, R4) or
  inside a named decision (tower `TenantSyncController`, `MachineIdentityReadGrant`, flagship
  `AuthorizeTenantProvisioning`).
- **L, the four repos unmeasured at origin**, scanned at their exact origin revisions in a whiffletree space
  (`cs05-origin`; `probeL-origin-four.txt`, HEAD = `ls-remote` origin for each): laravel-beam-exec 3d73335 (one Gate
  define, `synthetic.portfolios.manage`, a flat name: named), laravel-composition-spine c4aa187 (a domain `before()`
  interface: no decision), laravel-satellite-composition 7e58ebb (no hit), calcucrypt-tutorial effd0ab (web-guard
  session routes and `beam-docs.publish`: not bearer-reachable / named). Every registry repo is now scanned at origin
  or at a live sha whose delta to origin adds no probe hit.

Probe H is run on the flagship only. Other beam hosts (audiostud, numero, standwell, entreport, the starters) were
covered by probes A–G and I–K; a route-first run on each is part of R6.

## Ticket 07 (closed rows) and the remainder

Credential-scope 07 (space `cs07`, 2026-11-20) closed R1, R2, R4, R5 and Q1 in the rows above, each row naming its
commit. One seam each: R1 in beam's `ResourceReadGuard` (`inspect()` asks `inspectScopeFor()` for any admission that
did not go through a narrowed Gate decision; the relative-mount list asks it too); bespoke handlers and `GET /me` call
`ResourceReadGuard::authorizeScopedRead()` or name their decision; options sources that read another model register under
`filter-options:{ref}`. Every new name reaches the widest token set through `DecisionNames::offer()` (this package,
253d2cc) or a registration. R4 and part of R2 / R5 needed no change: the rows say why (session-only routes, a
refusal-only check before a named Gate decision, or a read reached only through a named one).

Still open:

- **R3** (held): entreport `CompanyController:171`, as above.
- **R6**, the route-first sweep (evidence `~/Workspaces/tmp/evidence/credential-scope/logs/07/r6/`). Flagship, probe
  H's 215 candidates (unit: routes), each classified (`flagship-215-classified.tsv`): 74 public by design (declared
  metadata: the 68 hook event catalogs, block manifest, declaration and context-scope schemas), 30 gated below the
  controller (a Gate decision in the write pipeline or the service, cited per row), 1 self-token only (logout), 11
  built in 07 (passkeys, `GET /me`, frame filters options and summary) or listed below (beam-tenancy
  `TenantMemberController` ×2), and 99 need a name (the census as classified, 2026-11-20). Other beam hosts (`other-hosts-summary.txt`, unit: bearer
  routes, `auth:sanctum` or a sanctum `auth:api`; every host's default guard is `web`): audiostud, calcucrypt, fable,
  schemastud, splicewire, stephenrushing, standwell and beam-pilot: 0 bearer routes; numero: 5 `auth:api` routes, all
  `ApiCaller::can`; the beam / satellite / commerce / market starters: one `GET api/user` closure each (a self read
  with no decision); the tower starter (`laravel-tower-starter`): 64 candidates, 42 need a name, plus its `api/user` closure (most shared
  with the flagship rows below).

  **Still outstanding (review cs07 reconciliation):** of the 68 controller methods the census classified as needing a
  name (unit: unique `Controller@method` across the flagship and the tower starter), 07 built 2 (the site report's
  heartbeat and uninstall, beam-market ee4a3fe) and closed 1 (`Tower\Api\V1\ThreadController@create` / `@update`,
  tower f9dd5e7: ThreadPolicy::update before any write), so **65 remain**, listed below. In routes: the flagship's 99
  less the 4 site-report routes and the 2 thread routes leaves **93**; the tower starter's 43 rows are unchanged. Each
  unbuilt method with its proposed name (the file:line and the proposed fix per route are in `flagship-215-summary.txt`
  and `other-hosts-summary.txt`):

| controller method | proposed name | host | where (origin) |
|---|---|---|---|
| `Tower\Api\V1\DereferenceController@show` | `fragment.view, fragment.{id}.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/DereferenceController.php:53-55 |
| `Tower\Api\V1\EmbeddingController@index` | `embedding.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/EmbeddingController.php:145 |
| `Tower\Api\V1\EmbeddingController@similar` | `embedding.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/EmbeddingController.php:110 |
| `Tower\Api\V1\HybridSearchController@search` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/HybridSearchController.php:46-67 |
| `Tower\Api\V1\KnowledgeGraphController@subgraph` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:77 |
| `Tower\Api\V1\KnowledgeGraphController@shortestPath` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:119 |
| `Tower\Api\V1\KnowledgeGraphController@detectCycles` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:161 |
| `Tower\Api\V1\KnowledgeGraphController@stats` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:174 |
| `Tower\Api\V1\KnowledgeGraphController@types` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:190 |
| `Tower\Api\V1\KnowledgeGraphController@entities` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:210 |
| `Tower\Api\V1\KnowledgeGraphController@describe` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:240 |
| `Tower\Api\V1\KnowledgeGraphController@query` | `fragment.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:276 |
| `Tower\Api\V1\KnowledgeGraphController@fragmentTriples` | `fragment.view, fragment.{id}.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:295 |
| `Tower\Api\V1\KnowledgeGraphController@reextract` | `fragment.update, fragment.{id}.update` | flagship, tower starter | tower@d87fc648 src/Api/V1/KnowledgeGraphController.php:313-315 |
| `Tower\Api\V1\FragmentUrlBatchController@index` | `fragment-url-batch.view (+ .own.view rows)` | flagship | tower@d87fc648 src/Api/V1/FragmentUrlBatchController.php:42 |
| `Tower\Api\V1\FragmentUrlBatchController@show` | `fragment-url-batch.view, fragment-url-batch.{id}.view` | flagship | tower@d87fc648 src/Api/V1/FragmentUrlBatchController.php:66 |
| `Tower\Determination\Http\Controllers\DeterminationOverviewController@show` | `entity.view (+ .own.view)` | flagship, tower starter | tower@d87fc648 src/Determination/Http/Controllers/DeterminationOverviewController.php:30-34 |
| `Tower\Api\V1\GraphOverviewController@show` | `concept.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/GraphOverviewController.php:32-41 |
| `Tower\Composition\Http\Controllers\StudioController@indexIdeas` | `composition-idea.view` | flagship, tower starter | tower@d87fc648 src/Composition/Http/Controllers/StudioController.php:43 |
| `Tower\Composition\Http\Controllers\StudioController@createIdea` | `composition-idea.create` | flagship, tower starter | tower@d87fc648 src/Composition/Http/Controllers/StudioController.php:69 |
| `Tower\Composition\Http\Controllers\StudioController@showIdea` | `composition-idea.view, composition-idea.{id}.view` | flagship, tower starter | tower@d87fc648 src/Composition/Http/Controllers/StudioController.php:48 |
| `Beam\Commerce\Http\Controllers\CreditsController@show` | `credits.view` | flagship | beam-commerce@599fac5 src/Http/Controllers/CreditsController.php:63-73 |
| `Beam\Commerce\Http\AutoReloadConfigController@show` | `auto-reload.view` | flagship | beam-commerce@599fac5 src/Http/AutoReloadConfigController.php:65-68 |
| `Beam\Commerce\Http\AutoReloadConfigController@activity` | `auto-reload.view` | flagship | beam-commerce@599fac5 src/Http/AutoReloadConfigController.php:133 |
| `Tower\Composition\Http\Controllers\StudioController@indexBriefs` | `composition-brief.view` | flagship, tower starter | tower@d87fc648 src/Composition/Http/Controllers/StudioController.php:82 |
| `Tower\Composition\Http\Controllers\StudioController@createBrief` | `composition-brief.create (+ composition-idea.{id}.update)` | flagship, tower starter | tower@d87fc648 src/Composition/Http/Controllers/StudioController.php:105-107 |
| `Tower\Composition\Http\Controllers\StudioController@showBrief` | `composition-brief.view, composition-brief.{id}.view` | flagship, tower starter | tower@d87fc648 src/Composition/Http/Controllers/StudioController.php:87 |
| `Tower\Api\V1\EvalRunController@store` | `context-scope.{id}.view + eval-run.create` | flagship | tower@d87fc648 src/Api/V1/EvalRunController.php:147 |
| `Tower\Api\V1\GoldenSetController@index` | `context-scope.view (+ .own.view)` | flagship | tower@d87fc648 src/Api/V1/GoldenSetController.php:46-49 |
| `Tower\Api\V1\ReleaseController@index` | `composition.own.view (+ composition.view)` | flagship | tower@d87fc648 src/Api/V1/ReleaseController.php:22 |
| `Tower\Api\V1\EntityIntakeController@store` | `entity.create` | flagship | tower@d87fc648 src/Api/V1/EntityIntakeController.php:122 |
| `Tower\Api\V1\EntityIntakeController@completeness` | `entity.view, entity.{id}.view` | flagship | tower@d87fc648 src/Api/V1/EntityIntakeController.php:197 |
| `Tower\Api\V1\EntityIntakeController@runs` | `entity.view, entity.{id}.view` | flagship | tower@d87fc648 src/Api/V1/EntityIntakeController.php:323 |
| `Tower\Api\V1\EntityIntakeController@reassess` | `entity.update, entity.{id}.update` | flagship | tower@d87fc648 src/Api/V1/EntityIntakeController.php:339 |
| `Tower\Api\V1\ModelStatusController@index` | `model-status.view (+ .own.view)` | flagship | tower@d87fc648 src/Api/V1/ModelStatusController.php:43 |
| `Tower\Api\V1\ModelStatusController@show` | `model-status.view, model-status.{id}.view` | flagship | tower@d87fc648 src/Api/V1/ModelStatusController.php:62 |
| `Tower\Api\V1\TenantInvitationController@index` | `invitation.view` | flagship | tower@d87fc648 src/Api/V1/TenantInvitationController.php:114 |
| `Tower\Api\V1\ApiTokenController@index` | `personal-access-token.view` | flagship | tower@d87fc648 src/Api/V1/ApiTokenController.php:64 |
| `Tower\Api\V1\ApiTokenController@store` | `personal-access-token.create` | flagship | tower@d87fc648 src/Api/V1/ApiTokenController.php:122 |
| `Tower\Api\V1\ApiTokenController@renew` | `personal-access-token.update, personal-access-token.{id}.update` | flagship | tower@d87fc648 src/Api/V1/ApiTokenController.php:250 |
| `Tower\Api\V1\ApiTokenController@rotate` | `personal-access-token.update, personal-access-token.{id}.update` | flagship | tower@d87fc648 src/Api/V1/ApiTokenController.php:284 |
| `Tower\Api\V1\ApiTokenController@destroyOtherSessions` | `personal-access-token.delete` | flagship | tower@d87fc648 src/Api/V1/ApiTokenController.php:382-385 |
| `Tower\Api\V1\ApiTokenController@destroy` | `personal-access-token.delete, personal-access-token.{id}.delete` | flagship | tower@d87fc648 src/Api/V1/ApiTokenController.php:208 |
| `Tower\Api\V1\ApiTokenController@archive` | `personal-access-token.update, personal-access-token.{id}.update` | flagship | tower@d87fc648 src/Api/V1/ApiTokenController.php:174 |
| `Tower\Api\V1\SystemModelsController@show` | `system-models.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/SystemModelsController.php:58-90 |
| `Tower\Api\V1\SystemModelsController@candidates` | `system-models.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/SystemModelsController.php:152-161 |
| `Tower\Api\V1\SystemModelsController@previewSpeech` | `system-models.preview-speech` | flagship, tower starter | tower@d87fc648 src/Api/V1/SystemModelsController.php:206 |
| `Tower\Api\V1\SystemModelsController@generateVideo` | `video-job.create` | flagship, tower starter | tower@d87fc648 src/Api/V1/SystemModelsController.php:234 |
| `Tower\Api\V1\SystemModelsController@videoJobs` | `video-job.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/SystemModelsController.php:252 |
| `Tower\Api\V1\SystemModelsController@videoJob` | `video-job.view, video-job.{id}.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/SystemModelsController.php:270 |
| `Tower\Api\V1\SystemModelsController@estimateEmbeddingSwitch` | `system-models.view` | flagship, tower starter | tower@d87fc648 src/Api/V1/SystemModelsController.php:316 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@permissions` | `personal-access-token.create` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:110 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@index` | `personal-access-token.view` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:89 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@store` | `personal-access-token.create` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:131 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@renew` | `personal-access-token.update, personal-access-token.{id}.update` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:155 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@rotate` | `personal-access-token.update, personal-access-token.{id}.update` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:183 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@destroyOtherSessions` | `personal-access-token.delete` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:295 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@destroy` | `personal-access-token.delete, personal-access-token.{id}.delete` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:263 |
| `Beam\Accounts\Http\Controllers\Account\ApiTokenController@archive` | `personal-access-token.update, personal-access-token.{id}.update` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/ApiTokenController.php:232 |
| `Beam\Accounts\Http\Controllers\Account\TeamInvitationController@index` | `invitation.view` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/TeamInvitationController.php:59 |
| `Beam\Accounts\Http\Controllers\Account\TeamInvitationController@send` | `{team-model}.manage-invitations` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/TeamInvitationController.php:82 |
| `Beam\Accounts\Http\Controllers\Account\TeamInvitationController@resend` | `{team-model}.manage-invitations` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/TeamInvitationController.php:104 |
| `Beam\Accounts\Http\Controllers\Account\TeamInvitationController@revoke` | `{team-model}.manage-invitations` | tower starter | beam-accounts@ff61517 src/Http/Controllers/Account/TeamInvitationController.php:132 |
| `Tower\Api\V1\WebSearchController@search` | `web-search.query` | tower starter | tower@d87fc648 src/Api/V1/WebSearchController.php:31-46 |
| `Closure [closure-or-invokable: outside the candidate filter, added]` | `user.view, user.{id}.view` | tower starter | routes/api.php:29-31 (tower |
| beam-tenancy `Http\Controllers\TenantMemberController@index` / `@roles` (2 routes; its writes already ask `manageMembers` through the Gate) | `{tenant}.view-members` | flagship | listed by 05 as R2, not in 07's space; outside the 65 above |
| starters' `GET api/user` closure (`routes/api.php:29-31`; tower starter `:120-122`) | `user.view`, `user.{id}.view` | beam, satellite, commerce, market, tower starters | remove it (`GET api/v1/me` serves the identity) or `Gate::authorize('view', $request->user())`; the tower starter's copy is the closure row above |

  Closed in 07 (orchestrator ruling): tower `ThreadController@create` / `@update` loaded a thread by a body or route `id`
  and saved it with no decision, so any member could rewrite any thread; tower f9dd5e7 asks `ThreadPolicy::update`
  before any read or write (real-bearer test: flagship `ThreadWriteIsAuthorizedTest`). Probe H counts an `entitlement:*` middleware as a gate; 18 such flagship rows were
  classified separately (`flagship-entitlement-only-classified.tsv`: 10 gated below, 6 public, 2 need a name, the
  `WebSearchController@search` row above). Frame summary providers other than the conduit handler's were not each
  proven.

## Names a token kind may need (for 03's widest set and 04's kinds)

`tenant.administer`, `tenant:provision` (Root arm), `tenants.sync` (Root arm), `concept.update` (corpus re-anchor),
`tenant.view` (seats list), `user.view` / `user.{id}.view` (chooser), `{key}.view` for each member-read resource
(`rules.view`, `evidence.view`, `review-queue.view`, …), `thread.own.view` / `thread.shared.view` (thread lists). Only
`tenant.administer` is not otherwise a permission or derivable name: it is registered in `DecisionNames` under
`require.admin`. `PATCH /me` asks `user.update` / `user.{id}.update`.

Added by credential-scope 07, each offered to the widest set: `{key}.view` for every particle resource (a read the guard
admits without a narrowed Gate decision), `me.view`, `passkey.view` / `.create` / `.update` / `.delete`,
`{team}.view-members` / `.manage-members`, `beam-ux-entry.traverse` / `.access` (the `root` sentinel),
`installed-extensions.report` (the connector's heartbeat and uninstall), `agent.view` / `agent.own.view`,
`circuit.view` / `circuit.own.view`, `silo.view`, `tag.view` (filter options), and the flagship's `operator.access`
(`require.root`). A consumer that reads particles now carries the resource's `{key}.view` (06 proves each kind).
