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
and 4 (`laravel-beam-exec`, `laravel-composition-spine`, `laravel-satellite-composition`, `calcucrypt-tutorial`) are
unmeasured at origin: no mirror holds both shas. `vendor*`, `tests`, `database`, `.compat` excluded. Evidence:
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
| `AuthenticatedReadPolicy`, `ActorOwnedParticleAccess` / `SharedParticleAccess` read arms, and `ResourceReadGuard`'s admissions by a tenancy or declared row scope with no policy | none asked | **open (R1)** |
| `SavedFilterService:108` owner compare (a restriction beside the Gate's `update` / `delete` on the saved filter) | `saved-filter.*` | named |
| deprecated `Splicewire\Beam\Authorization\CredentialScopeGate` alias | — | removed (05) |

### splicewire/laravel-beam-accounts

| decision | name | status |
|---|---|---|
| `UserPolicy` (self arm, Root arm) | `user.{verb}`, `user.{id}.{verb}` | named (02, #39) |
| `InvitationPolicy`, team-role fallback | `invitation.*` | named (#39) |
| `TokenPolicy` | `personal-access-token.*` | named |
| `MembershipPolicy` via `manageMembers` / `manageInvitations` / `manageInvitation` (always asked with a team / invitation) | `{team-model}.manage-members`, `.manage-invitations`, `invitation.manage-invitation` (+ `{id}`) | named (derived) |
| `ux.author`, `ux.{realm}.author`, `request-{key}-access` (on a model) | themselves / derived | named |
| `TeamMemberReadPolicy` (member arm), `InvitationReadPolicy`, `MePolicy` (read policies) | none asked | **open (R1)** |
| `PasskeyController:104,121` (owner `abort_unless` on the session API, reachable with `auth:sanctum`) | none asked | **open (R2)** |
| `UsersQuery:42` Root reads every user (a row scope) | none asked | **open (R2)** |
| `Account\TeamMemberController` membership and owner reads (`index`, `roles`, `updateRole`, `remove`: `NotTeamMember`, `TeamOwnerRequired`) and `TeamMembers:73,98` | none asked | **open (R2)** |
| `ImpersonateUser:66` self refusal (a refusal, inside an op with `ability:`) | the op's | named |

### splicewire/laravel-beam-market

| decision | name | status |
|---|---|---|
| `SellerRepoAuthorizationPolicy` | `seller-repo-authorization.*` | named |
| `reviewMarketListing` (Root-only define) | `reviewMarketListing` (registered) | named (02) |
| `TenantReportingSite:42` membership read for heartbeat / uninstall | none asked | **open (R2)**; the device-flow consumer (C8) must gain the name first |
| `MarketProductRowScope:113` Root sees every product (row scope) | none asked | **open (R2)** |
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
| beam-ux | `TokenAccessGate:108`: an entry's `root` access token is a Root role read (its `<alias>.<verb>` tokens ask `can()` and are named) | **open (R2)** |
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
| `ReviewInbox:194` awaiting rows by the user's role tokens | none asked | **open (R2)** |
| `Navigation\Gates\AccessGate:65` Root nav token | an offer, not an authority | not reachable as a grant |
| `PolishPolicy`, `MaterializationPolicy`, federation `*ResolutionPolicy` / `CorpusAudiencePolicy` | — | no decision (domain objects) |

### splicewire/splicewire-app (the flagship)

| decision | name | status |
|---|---|---|
| `RunnerTransformPolicy` (Root arm) | `runner-transform.*` | named (#39) |
| Root `Gate::before`; `ux.author` / manifest `viewAny` / records befores through `site.edit` | `superuser()`; the outer name, then `site.edit` | named (#39, 02) |
| `entitlement:os.operate`, `exec.view`, `analytics.view` definitions | — | exempt (C4); see Q1 |
| `analytics.destination.*`, `activity.resource.read` | themselves | named |
| `HopController::issue` | refused for any scoped token | named (02, C9) |
| `RequireAdminRole` (`require.admin`) and `RoleReachabilityProbe` admin arm | `tenant.administer` (registered under `require.admin`) | named (05) |
| `AuthorizeTenantProvisioning` Root arm | `tenant:provision` | named (05) |
| `ChooserController` (the reader's own record) | `user.view`, `user.{id}.view` (routed through `UserPolicy::view`) | named (05) |
| `RoleReachabilityProbe` root arm | asks `entitlement:os.operate`, as `RequireRootRole` does | exempt (C4); see Q1 |
| `RequireRootRole` (`require.root` → `entitlement:os.operate`, defined as `isRoot`) | — | exempt by C4, but a Root grant by C3: **Q1** |
| `WorkflowExecutionAuthority:56` membership read | none asked | **open (R2)** |
| `viewHorizon` (web guard) | — | fail-closed; not reachable by a bearer |
| `HostTenant`, `TenantLandingSeats`, `routes/web.php:116` membership reads | — | not reachable (session landing) |
| `EngineConsumerToken:143` Admin read | — | a mint site: ticket 04 |
| `Dev\SubstrateChatController` `create` / `update` | — | not reachable (dev only) |

### Sites and starters

| repo | decisions | status |
|---|---|---|
| rushing/standwell | `Gate::define`d `documents.*`, `exposures.remediate`, `assessments.scan`, `packet-shares.view`, `source-connections.*`, `agreement-values.dispute`, `received-packets.view`, … (membership / owner role inside: the principal half) | named (flat) |
| rushing/standwell | `MerchantWorkspaceModelPolicy` | named (derived) |
| rushing/standwell | `MerchantWorkspaceReadPolicy`, `ReceivedPacketReadPolicy`, `ShareRecipientReadPolicy` (read policies) | **open (R1)**, fixed centrally in beam, not in standwell |
| rushing/standwell | `StandwellWorkflowActionAuthority:39` principal compare, then `Gate::authorize('view', $subject)` | named (derived) |
| rushing/standwell | `bypass-marquee` | fail-closed |
| rushing/entreport (held: read-only here) | `CompanyController:171` owner `abort_unless` (no policy, no Gate decision) | **open (R3)**: needs `company.view` / `company.{id}.view` (or a `CompanyPolicy` whose verbs derive them) |
| splicewire/audiostud | `RankPolicy`, `RankTreePolicy`, `SteeringProfilePolicy`; `ux.author`, realm author abilities; `create` / `update` on a `BeamParticle` | named |
| splicewire/audiostud | `AuthenticatedResourceReadPolicy`, `PublicResourceReadPolicy`, `OperatorResourceReadPolicy` | **open (R1)** |
| splicewire/audiostud | ownership reads in `StudioController:391,475,493`, `SheetMusicController:59`, `SongController:101`, `ReportController:48`, ops `ChooseTake:21`, `ListTakes:21`, `TakeIteration:32-33`, `SubmitTimelineRegeneration:32-33` | **open (R4)** |
| splicewire/numero | `NumerologyResourcePolicy`, `VisibilityPolicy`; `bypass-marquee` | named / fail-closed |
| splicewire/numero | `SubjectAccess:96` owner read, `GrantController:55`, `Operator\EntitlementRefundController:42` | **open (R4)** |
| stephenrushing (site) | `WorkspaceResourcePolicy::before` (site owner email), `bypass-marquee` | named (derived verbs) / fail-closed |
| calcucrypt, calcucrypt-tutorial | `CalculatorPolicy`, `PostPolicy`, `SavedInputPolicy`; `ux.author`, `beam-docs.publish` | named |
| starters (beam, satellite, commerce, market, tower) | `beam-docs.publish`, `ux.{realm}.author`, `site.edit`, `commerce.manage`, `market-extensions.install`, `installed-extensions.*`, `market-connections.sync` (Root or role inside: the principal half) | named (flat) |
| laravel-tower-starter example `ServiceRequestPolicy` | derived | named |
| thingsontv | `Role` middleware, `isAdmin()`, `viewHorizon` | not a beam-accounts host: no scope source is bound, so no token is scoped there (ADR 0006 rule 3 makes that a 04/06 question) |
| fable-legacy | its policies, `before`, 27 inline reads | out of scope (credential-scope 04 ruling: not a beam host) |
| rushing/* domain packages (`augmentation-loop`, `commerce`, `notification-status`, `postgres-rls`, `surgeon`), schemastud/*, conduit-ecfr, composition / knowledge spines, satellite-training | "Policy" domain objects only | no decision (probe A hits; B–F none) |

Every other registry PHP repo: no hit on any of probes A–F.

## Remainder (open rows)

- **R1, beam (one site, many repos):** `ResourceReadGuard` admits a read through a `ResourceReadPolicy` or a tenancy or
  declared row scope without asking any name. Fix once in beam: under a scope, a read the guard admits other than
  through a Gate decision asks `carries($actor, ["{$key}.view", …derived {model}.view])`. It covers beam
  (`AuthenticatedReadPolicy`, the particle-access read arms), beam-accounts (`TeamMemberReadPolicy`,
  `InvitationReadPolicy`, `MePolicy`), audiostud's and standwell's read policies, and every resource with no policy.
  Consumer cost: each token kind that reads particle resources must carry `{key}.view` (06 proves it).
- **R2, inline reads in packages and the flagship:** beam-accounts `PasskeyController`, `UsersQuery`, `TeamMemberController`; beam-ux `TokenAccessGate` `root`; beam-market
  `TenantReportingSite` (the device-flow heartbeat consumer must gain the name first), `MarketProductRowScope`; tower
  `ReviewInbox`; flagship `WorkflowExecutionAuthority`.
- **R3, rushing/entreport (held):** `CompanyController:171` needs a named decision (`company.view`,
  `company.{id}.view`), best as a `CompanyPolicy` so the derivation names it.
- **R4, sites:** audiostud's ten ownership reads and numero's three.
- **Q1, a ruling:** the flagship defines `entitlement:os.operate` (and the Root arms of `exec.view`, `analytics.view`) as
  `BeamAccounts::isRoot`, so `require.root` and every operator-realm door is a Root grant answered principal-only under
  C4. C3 says a Root grant passes a scoped Root token only with the decision's name. Recommendation: the entitlement
  plane stays exempt, and `RequireRootRole` also asks the scope for a registered name (`operator.access`), as
  `require.admin` now does.

## Names a token kind may need (for 03's widest set and 04's kinds)

`tenant.administer`, `tenant:provision` (Root arm), `tenants.sync` (Root arm), `concept.update` (corpus re-anchor),
`tenant.view` (seats list), `user.view` / `user.{id}.view` (chooser), `{key}.view` for each member-read resource
(`rules.view`, `evidence.view`, `review-queue.view`, …), `thread.own.view` / `thread.shared.view` (thread lists). Only
`tenant.administer` is not otherwise a permission or derivable name: it is registered in `DecisionNames` under
`require.admin`.
