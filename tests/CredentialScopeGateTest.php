<?php

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Rushing\PermissionCascade\Authorization\CredentialScopeGate;
use Rushing\PermissionCascade\Authorization\CredentialScopeRefusal;
use Rushing\PermissionCascade\Authorization\CredentialScopeRefused;
use Rushing\PermissionCascade\Authorization\DecisionNames;
use Rushing\PermissionCascade\Policies\ConfiguredModelPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\AccessGrant;
use Rushing\PermissionCascade\Tests\Fixtures\Post;
use Rushing\PermissionCascade\Tests\Fixtures\PostPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\Seal;
use Rushing\PermissionCascade\Tests\Fixtures\SealPolicy;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;
use Rushing\PermissionCascade\Tests\Fixtures\WidgetPolicy;

/**
 * Fleet ADR 0006 rule 1 (credential-scope 02): a scoped credential fails closed. For the acting principal under a
 * scope, every Gate decision is "the principal may AND the token carries the decision's name"; a decision with no name
 * refuses the scoped token with a coded 403. Session, guest, `*` and another principal's check are unchanged, and the
 * entitlement plane stays principal-only.
 *
 * The before is registered here the way beam registers it in a host: first, ahead of every other before.
 */
beforeEach(function () {
    actingTeam(1);
    CredentialScopeRefusal::describeUsing(null);

    Gate::before(fn ($user = null, $ability = null, $arguments = []) => app(CredentialScopeGate::class)
        ->before($user, $ability, $arguments));

    $this->member = User::create(['name' => 'Member', 'email' => 'member@example.test']);
    $this->other = User::create(['name' => 'Other', 'email' => 'other@example.test']);
    $this->root = ScopedRootUser::create(['name' => 'Root', 'email' => 'root@example.test']);

    // The principal's flat permissions (a Gate definition each, so the principal half is explicit).
    Gate::define('widgets.export', fn ($user = null) => $user !== null && $user->email !== 'other@example.test');
    Gate::define('widgets.approve', fn ($user = null) => $user !== null && $user->email !== 'other@example.test');
    Gate::define('widgets.public', fn ($user = null) => true);
    Gate::define('entitlement:widgets.premium', fn ($user = null) => true);
    Gate::define('entitlement:widgets.insight', fn ($user = null) => $user !== null && $user->can('widgets.export'));

    // C1's fixtures: a decision that names nothing. A subjectless ability, and a policy over a subject that is no model.
    Gate::define('rebootFleet', fn ($user = null) => true);
    Gate::policy(ScopedReport::class, ScopedReportPolicy::class);

    // A policy outside the cascade: membership / ownership arms that ask no permission, and a verb that asks one.
    Gate::policy(ScopedGadget::class, ScopedGadgetPolicy::class);

    // A host superuser before (the flagship's Root), made scope-aware through the seam.
    Gate::before(fn ($user = null, $ability = null, $arguments = []) => $user instanceof ScopedRootUser
        ? app(CredentialScopeGate::class)->superuser($user, $ability, is_array($arguments) ? $arguments : [$arguments])
        : null);

    Route::get('/scoped/flat', fn () => tap(['ok' => true], fn () => Gate::authorize('widgets.export')));
    Route::get('/scoped/can', fn () => ['ok' => true])->middleware('can:widgets.export');
    Route::get('/scoped/reboot', fn () => tap(['ok' => true], fn () => Gate::authorize('rebootFleet')));
    Route::get('/scoped/report/{verb}', fn (string $verb) => tap(['ok' => true], fn () => Gate::authorize($verb, new ScopedReport)));
    Route::get('/scoped/gadgets/{id}/{verb}', fn (string $id, string $verb) => tap(['ok' => true],
        fn () => Gate::authorize($verb, ScopedGadget::query()->findOrFail($id))));
    Route::get('/scoped/entitlement', fn () => tap(['ok' => true], fn () => Gate::authorize('entitlement:widgets.premium')));
    Route::get('/scoped/insight', fn () => tap(['ok' => true], fn () => Gate::authorize('entitlement:widgets.insight')));
    Route::get('/scoped/public', fn () => tap(['ok' => true], fn () => Gate::authorize('widgets.public')));
    Route::get('/scoped/other-user', fn () => ['other' => Gate::forUser(User::query()->where('email', 'member@example.test')->first())->allows('widgets.export')]);

    $this->mine = ScopedGadget::create(['name' => 'mine', 'user_id' => $this->member->id]);
    $this->theirs = ScopedGadget::create(['name' => 'theirs', 'user_id' => $this->other->id]);
});

afterEach(fn () => CredentialScopeRefusal::describeUsing(null));

// ── C1: a decision that names nothing ───────────────────────────────────────────────────

it('refuses a scoped token at a decision that names nothing, with a coded 403', function () {
    $this->actingAs($this->member);
    bindScope(['widgets.export', 'rebootFleet', 'scoped-report.view']);

    $this->getJson('/scoped/reboot')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::UNNAMED]);
    $this->getJson('/scoped/report/view')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::UNNAMED]);
    expect(Gate::allows('rebootFleet'))->toBeFalse()
        ->and(Gate::inspect('rebootFleet')->code())->toBe(CredentialScopeRefusal::UNNAMED);
});

it('gives a session, a star token and a guest the unnamed decision\'s own answer', function () {
    // A session or a `*` token: no scope in force.
    $this->actingAs($this->member);
    bindScope(null);
    $this->getJson('/scoped/reboot')->assertOk();
    $this->getJson('/scoped/report/view')->assertOk();
    $this->getJson('/scoped/report/destroy')->assertForbidden(); // the policy's own refusal, not the scope's

    // A guest: there is no credential to narrow.
    Auth::logout();
    bindScope([]);
    $this->getJson('/scoped/public')->assertOk();
});

it('admits a decision named through the registry or the host config, only when the token carries the name', function () {
    app(DecisionNames::class)->name('rebootFleet', 'fleet.reboot');
    app(DecisionNames::class)->name('view', fn (array $arguments) => ['report.view'], ScopedReport::class);
    $this->actingAs($this->member);

    bindScope(['widgets.export']);
    $this->getJson('/scoped/reboot')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);
    $this->getJson('/scoped/report/view')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);

    bindScope(['fleet.reboot', 'report.view']);
    $this->getJson('/scoped/reboot')->assertOk();
    $this->getJson('/scoped/report/view')->assertOk();

    config(['permission-cascade.decision_names' => ['restartQueue' => 'queue.restart']]);
    Gate::define('restartQueue', fn ($user = null) => true);
    expect(Gate::allows('restartQueue'))->toBeFalse();
    bindScope(['queue.restart']);
    expect(Gate::allows('restartQueue'))->toBeTrue();
});

// ── C2: membership and ownership decisions are named, reads and writes alike ───────────

it('refuses a membership or ownership decision a scoped token does not name, reads and writes alike', function () {
    $this->actingAs($this->member);
    bindScope(['widgets.export']);

    $this->getJson("/scoped/gadgets/{$this->mine->id}/view")->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);
    $this->getJson("/scoped/gadgets/{$this->mine->id}/update")->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);

    // The derived names admit: `{model}.{verb}` and `{model}.{id}.{verb}`.
    bindScope(['scoped-gadget.view', "scoped-gadget.{$this->mine->id}.update"]);
    $this->getJson("/scoped/gadgets/{$this->mine->id}/view")->assertOk();
    $this->getJson("/scoped/gadgets/{$this->mine->id}/update")->assertOk();
});

it('still refuses a token carrying the name for a record its user does not own (the principal half)', function () {
    $this->actingAs($this->member);
    bindScope(['scoped-gadget.view', 'scoped-gadget.update']);

    $this->getJson("/scoped/gadgets/{$this->mine->id}/update")->assertOk();
    $this->getJson("/scoped/gadgets/{$this->theirs->id}/update")->assertForbidden();
    $this->getJson("/scoped/gadgets/{$this->theirs->id}/view")->assertForbidden();
});

it('needs the decision name and every name the policy asks: a verb is no longer named by what it asks inside', function () {
    $this->actingAs($this->member);

    // `approve` asks `widgets.approve` inside. That name alone no longer admits the verb (#39 narrowed only the inside).
    bindScope(['widgets.approve']);
    $this->getJson("/scoped/gadgets/{$this->mine->id}/approve")->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);

    // The verb's name alone admits the decision, and the permission it asks is still narrowed.
    bindScope(['scoped-gadget.approve']);
    $this->getJson("/scoped/gadgets/{$this->mine->id}/approve")->assertForbidden();

    bindScope(['scoped-gadget.approve', 'widgets.approve']);
    $this->getJson("/scoped/gadgets/{$this->mine->id}/approve")->assertOk();
});

it('narrows a flat name asked by a controller or a can middleware, and leaves an unscoped call alone', function () {
    $this->actingAs($this->member);

    bindScope(['widgets.approve']);
    $this->getJson('/scoped/flat')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);
    $this->getJson('/scoped/can')->assertForbidden();

    bindScope(['widgets.export']);
    $this->getJson('/scoped/flat')->assertOk();
    $this->getJson('/scoped/can')->assertOk();

    bindScope(null);
    $this->getJson('/scoped/flat')->assertOk();
    $this->getJson('/scoped/gadgets/'.$this->mine->id.'/view')->assertOk();
});

// ── BaseModelPolicy: every rung, the ones that ask no permission included ──────────────

it('admits a cascade verb by any of its rung names and narrows the steward and shared rungs', function () {
    Gate::policy(Post::class, PostPolicy::class);
    $this->actingAs($this->member);

    $owned = Post::create(['name' => 'owned', 'user_id' => $this->member->id, 'visibility' => 'private']);
    $shared = Post::create(['name' => 'shared', 'user_id' => $this->other->id, 'visibility' => 'private']);
    AccessGrant::create([
        'grantable_type' => 'post', 'grantable_id' => $shared->id,
        'grantee_type' => $this->member->getMorphClass(), 'grantee_id' => $this->member->id,
        'ability' => 'view', 'effect' => 'allow',
    ]);

    // Unscoped: the steward and the explicit grant answer, with no token.
    bindScope(null);
    expect(Gate::allows('view', $owned))->toBeTrue()->and(Gate::allows('view', $shared))->toBeTrue();

    // A scope naming nothing about posts: both refused before the policy runs.
    bindScope(['widgets.export']);
    expect(Gate::inspect('view', $owned)->code())->toBe(CredentialScopeRefusal::NOT_CARRIED)
        ->and(Gate::allows('view', $shared))->toBeFalse();

    // `.own.` names the steward rung only; the shared post stays refused.
    bindScope(['post.own.view']);
    expect(Gate::allows('view', $owned))->toBeTrue()->and(Gate::allows('view', $shared))->toBeFalse();

    // `.shared.` names the grant and tier rungs only; the steward rung stays refused.
    bindScope(['post.shared.view']);
    expect(Gate::allows('view', $owned))->toBeFalse()->and(Gate::allows('view', $shared))->toBeTrue();

    // The action's own name covers every rung, still only where the principal may.
    bindScope(['post.view']);
    expect(Gate::allows('view', $owned))->toBeTrue()->and(Gate::allows('view', $shared))->toBeTrue();
    $foreign = Post::create(['name' => 'foreign', 'user_id' => $this->other->id, 'visibility' => 'private']);
    expect(Gate::allows('view', $foreign))->toBeFalse();
});

it('narrows the morph owner\'s inherent authority', function () {
    Gate::policy(Seal::class, SealPolicy::class);
    $this->actingAs($this->member);
    $seal = Seal::create(['name' => 's', 'visibility' => 'private', 'user_type' => $this->member->getMorphClass(), 'user_id' => (string) $this->member->id]);

    bindScope(null);
    expect(Gate::allows('delete', $seal))->toBeTrue();

    bindScope(['seal.view']);
    expect(Gate::allows('delete', $seal))->toBeFalse();
    bindScope(['seal.own.view']);
    expect(Gate::allows('delete', $seal))->toBeFalse();
    // `.shared.` admits the decision but names only the grant and tier rungs: the owner's inherent arm stays refused.
    bindScope(['seal.shared.delete']);
    expect(Gate::allows('delete', $seal))->toBeFalse();
    bindScope(['seal.own.delete']);
    expect(Gate::allows('delete', $seal))->toBeTrue();
});

it('names a cascade verb through its rungs and viewAny through view', function () {
    $widget = Widget::create(['name' => 'w']);
    $policy = new WidgetPolicy;

    expect($policy->decisionNames('viewAny', [Widget::class]))->toBe(['widget.view', 'widget.own.view'])
        ->and($policy->decisionNames('update', [$widget]))->toBe(['widget.update', 'widget.own.update', "widget.{$widget->id}.update", 'widget.shared.update'])
        ->and($policy->decisionNames('publish', [$widget]))->toBeNull()
        ->and(app(CredentialScopeGate::class)->namesFor('forceDelete', [ScopedGadget::class]))->toBe(['scoped-gadget.forcedelete', 'scoped-gadget.force-delete'])
        ->and(app(CredentialScopeGate::class)->namesFor('rebootFleet'))->toBe([]);
});

it('names an overridden cascade verb by its derived names only, never by the rungs it no longer runs', function () {
    // codex cs02 (blocking 1): a subclass that overrides `view` (tower ConduitPolicy admits any authenticated user)
    // must not inherit `.own.` / `.shared.` names for it; the verbs it keeps still carry every rung name.
    Gate::policy(Post::class, ScopedOpenPostPolicy::class);
    $this->actingAs($this->member);
    $foreign = Post::create(['name' => 'foreign', 'user_id' => $this->other->id, 'visibility' => 'private']);

    bindScope(null);
    expect(Gate::allows('view', $foreign))->toBeTrue();

    foreach (['post.own.view', 'post.shared.view'] as $rung) {
        bindScope([$rung]);
        expect(Gate::inspect('view', $foreign)->code())->toBe(CredentialScopeRefusal::NOT_CARRIED);
    }
    bindScope(['post.view']);
    expect(Gate::allows('view', $foreign))->toBeTrue();

    expect((new ScopedOpenPostPolicy)->decisionNames('view', [$foreign]))->toBeNull()
        ->and((new ScopedOpenPostPolicy)->decisionNames('update', [$foreign]))->toContain('post.own.update', 'post.shared.update');
});

it('lets a subclass that guards a verb and still runs the rungs declare their names (credential-scope 05)', function () {
    // tower ThreadPolicy::view refuses a session thread, then defers to the cascade's rungs: it declares the rung names
    // through cascadeRungNames(), so a token carrying `post.own.view` reaches the own rung, and the guard still decides.
    Gate::policy(Post::class, ScopedGuardedPostPolicy::class);
    grantPermission($this->member, 'post.own.view');
    $this->actingAs($this->member);
    $mine = Post::create(['name' => 'mine', 'user_id' => $this->member->id, 'visibility' => 'private']);
    $guarded = Post::create(['name' => 'guarded', 'user_id' => $this->member->id, 'visibility' => 'private']);
    $foreign = Post::create(['name' => 'foreign', 'user_id' => $this->other->id, 'visibility' => 'private']);

    bindScope(['post.own.view']);
    expect(Gate::allows('view', $mine))->toBeTrue()
        ->and(Gate::allows('view', $guarded))->toBeFalse()
        ->and(Gate::allows('view', $foreign))->toBeFalse();
    bindScope(['widgets.export']);
    expect(Gate::inspect('view', $mine)->code())->toBe(CredentialScopeRefusal::NOT_CARRIED);

    expect((new ScopedGuardedPostPolicy)->decisionNames('view', [$mine]))->toContain('post.own.view', 'post.shared.view')
        ->and((new ScopedOpenPostPolicy)->decisionNames('view', [$mine]))->toBeNull();
});

it('names a configured verb answered by an override, or replaced by a subclass, by its derived names only', function () {
    $widget = Widget::create(['name' => 'w']);

    $configured = new ConfiguredModelPolicy(Widget::class, ['view' => true]);
    expect($configured->decisionNames('view', [$widget]))->toBeNull()
        ->and($configured->decisionNames('update', [$widget]))->toContain('widget.own.update');

    $replaced = new ScopedReplacedConfiguredPolicy(Widget::class);
    expect($replaced->decisionNames('create', [Widget::class]))->toBeNull()
        ->and($replaced->decisionNames('delete', [$widget]))->toContain('widget.own.delete');

    // Through the Gate: the override answers `true`, and a rung name no longer reaches it.
    Gate::policy(Widget::class, ScopedViewOverrideWidgetPolicy::class);
    $this->actingAs($this->member);
    bindScope(['widget.own.view']);
    expect(Gate::allows('view', $widget))->toBeFalse();
    bindScope(['widget.view']);
    expect(Gate::allows('view', $widget))->toBeTrue();
});

// ── the names a widest token may carry (credential-scope 04) ──────────────────────────────

it('offers every registered name and each policy verb\'s class-level names, never a per-record name or a closure\'s', function () {
    app(DecisionNames::class)->name('join', fn (array $arguments) => ['team.'.$arguments[0]->getKey().'.join']);
    config(['permission-cascade.decision_names' => ['viewPulse' => 'pulse.view']]);
    expect(app(CredentialScopeGate::class)->offerableNames())->not->toContain('fleet.reboot');
    app(DecisionNames::class)->name('rebootFleet', 'fleet.reboot');
    Gate::policy(Widget::class, WidgetPolicy::class);
    $gadget = $this->mine;

    $offered = app(CredentialScopeGate::class)->offerableNames();

    expect($offered)->toContain('fleet.reboot', 'pulse.view')
        // a policy outside the cascade: each public verb by its derivation on the class
        ->toContain('scoped-gadget.view', 'scoped-gadget.update', 'scoped-gadget.approve')
        // a cascade policy: its declared rung names on the class (`viewAny` by `view`)
        ->toContain('widget.view', 'widget.own.view', 'widget.update', 'widget.own.update', 'widget.force-delete')
        ->not->toContain("scoped-gadget.{$gadget->id}.view", '*', 'widget.decisionnames', 'widget.scopeforuser', 'widget.scope-for-user');

    foreach ($offered as $name) {
        expect($name)->not->toMatch('/\.\d+\./')->not->toStartWith('team.');
    }

    // Flat named Gate definitions offer their own permission-shaped name (codex cs04 #3); an unnamed one offers nothing,
    // and an entitlement is principal-only, so it is never offered.
    expect($offered)->toContain('widgets.export', 'widgets.approve', 'widgets.public')
        ->not->toContain('rebootFleet', 'entitlement:widgets.premium', 'entitlement:widgets.insight');

    // A subject that is no model (ScopedReport) offers nothing derived: there is no class name to derive from.
    expect($offered)->not->toContain('scoped-report.view');
});

// ── C3: a superuser grant is narrowed ───────────────────────────────────────────────────

it('does not carry a scoped superuser past a decision whose name the token lacks', function () {
    $this->actingAs($this->root);

    bindScope(['widgets.export']);
    $this->getJson('/scoped/flat')->assertOk();
    $this->getJson("/scoped/gadgets/{$this->theirs->id}/update")->assertForbidden();
    // A custom verb no policy method defines: only the superuser before ever answered it.
    $this->getJson("/scoped/gadgets/{$this->theirs->id}/reset")->assertForbidden();
    $this->getJson('/scoped/reboot')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::UNNAMED]);

    // The derived names admit the superuser's grant, per class or per instance.
    bindScope(['scoped-gadget.update', "scoped-gadget.{$this->theirs->id}.reset"]);
    $this->getJson("/scoped/gadgets/{$this->theirs->id}/update")->assertOk();
    $this->getJson("/scoped/gadgets/{$this->theirs->id}/reset")->assertOk();
    $this->getJson('/scoped/flat')->assertForbidden();

    // Unscoped: the superuser passes everything, as before.
    bindScope(null);
    $this->getJson('/scoped/reboot')->assertOk();
    $this->getJson("/scoped/gadgets/{$this->theirs->id}/reset")->assertOk();
});

it('answers superuserMay by the strict name only, never by an ownership rung', function () {
    $this->actingAs($this->root);
    $gate = app(CredentialScopeGate::class);

    bindScope(['widget.own.update']);
    expect($gate->superuserMay($this->root, 'update', Widget::class))->toBeFalse();
    bindScope(['widget.update']);
    expect($gate->superuserMay($this->root, 'update', Widget::class))->toBeTrue()
        ->and($gate->superuserMay($this->root, 'rebootFleet'))->toBeFalse();
    app(DecisionNames::class)->name('rebootFleet', 'fleet.reboot');
    bindScope(['fleet.reboot']);
    expect($gate->superuserMay($this->root, 'rebootFleet'))->toBeTrue();
});

// ── a check outside the Gate (credential-scope 05) ─────────────────────────────────────

it('answers an inline check by the scope: carries() and authorizeCarried() for the acting principal only', function () {
    $gate = app(CredentialScopeGate::class);
    Route::match(['get', 'post'], '/scoped/inline', fn () => tap(['ok' => true], fn () => $gate->authorizeCarried(auth()->user(), 'require.admin', ['tenant.administer'])));

    // Unscoped (a session; the token resolver answers null for a `*` token): the inline check is the principal's alone.
    $this->actingAs($this->member);
    bindScope(null);
    expect($gate->carries($this->member, 'tenant.administer'))->toBeTrue();
    $this->getJson('/scoped/inline')->assertOk();
    $this->postJson('/scoped/inline')->assertOk();

    // Scoped without the name: refused with the same code a Gate decision gives, reads and writes alike.
    bindScope(['widgets.export']);
    expect($gate->carries($this->member, 'tenant.administer'))->toBeFalse()
        ->and($gate->carries($this->member, ['other.name', 'widgets.export']))->toBeTrue();
    $this->getJson('/scoped/inline')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);
    $this->postJson('/scoped/inline')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);

    // Scoped with the name: admitted; the inline check itself still decides for the principal.
    bindScope(['tenant.administer']);
    $this->getJson('/scoped/inline')->assertOk();
    $this->postJson('/scoped/inline')->assertOk();

    // Another principal's check is not the token's.
    bindScope(['widgets.export']);
    expect($gate->carries($this->other, 'tenant.administer'))->toBeTrue();
});

it('names an inline check through the registry when the caller passes no names, and refuses an unnamed one', function () {
    $gate = app(CredentialScopeGate::class);
    Route::get('/scoped/inline-registered', fn () => tap(['ok' => true], fn () => $gate->authorizeCarried(auth()->user(), 'require.owner')));
    $this->actingAs($this->member);

    // Nothing registered: no name a token can carry.
    bindScope(['tenant.own']);
    $this->getJson('/scoped/inline-registered')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::UNNAMED]);

    app(DecisionNames::class)->name('require.owner', 'tenant.own');
    $this->getJson('/scoped/inline-registered')->assertOk();
    bindScope(['widgets.export']);
    $this->getJson('/scoped/inline-registered')->assertForbidden()->assertJson(['code' => CredentialScopeRefusal::NOT_CARRIED]);

    // Unscoped: the inline check is the principal's alone.
    bindScope(null);
    $this->getJson('/scoped/inline-registered')->assertOk();
});

// ── C4: the entitlement plane stays principal-only ─────────────────────────────────────

it('leaves the entitlement plane principal-only, while the permission it asks stays narrowed when asked directly', function () {
    $this->actingAs($this->member);
    bindScope([]);
    $this->getJson('/scoped/entitlement')->assertOk();

    bindScope(['widgets.approve']);
    $this->getJson('/scoped/insight')->assertOk();
    $this->getJson('/scoped/flat')->assertForbidden();
    expect(Gate::allows('widgets.export'))->toBeFalse()
        ->and(Gate::allows('entitlement:widgets.insight'))->toBeTrue()
        ->and(Gate::allows('widgets.export'))->toBeFalse();

    // A principal the definition refuses is still refused.
    $this->actingAs($this->other);
    $this->getJson('/scoped/insight')->assertForbidden();
});

// ── who is narrowed ─────────────────────────────────────────────────────────────────────

it('narrows only the acting principal: another user\'s check and a named guard\'s principal', function () {
    $this->actingAs($this->other);
    bindScope([]);
    $this->getJson('/scoped/other-user')->assertOk()->assertJson(['other' => true]);
    $this->getJson('/scoped/flat')->assertForbidden();

    // A named bearer guard holds the principal while the default guard is empty.
    Auth::logout();
    $principal = $this->member;
    Auth::viaRequest('cs02-probe', fn () => $principal);
    config(['auth.guards.cs02-probe' => ['driver' => 'cs02-probe']]);
    Route::get('/scoped/named-guard', fn () => ['self' => Gate::forUser(auth('cs02-probe')->user())->allows('widgets.export')]);
    bindScope(['widgets.approve']);
    $this->getJson('/scoped/named-guard')->assertOk()->assertJson(['self' => false]);
    bindScope(['widgets.export']);
    $this->getJson('/scoped/named-guard')->assertOk()->assertJson(['self' => true]);
});

// ── the coded refusal ───────────────────────────────────────────────────────────────────

it('throws a coded authorization exception whose message a host can localize', function () {
    $this->actingAs($this->member);
    bindScope(['widgets.approve']);

    try {
        Gate::authorize('widgets.export');
        $this->fail('expected a refusal');
    } catch (CredentialScopeRefused $e) {
        expect($e->errorCode())->toBe(CredentialScopeRefusal::NOT_CARRIED)
            ->and($e->status())->toBe(403);
    }

    CredentialScopeRefusal::describeUsing(fn (string $code) => "localized {$code}");
    $this->getJson('/scoped/reboot')->assertForbidden()
        ->assertExactJson(['message' => 'localized '.CredentialScopeRefusal::UNNAMED, 'code' => CredentialScopeRefusal::UNNAMED]);
});

// ── fixtures ────────────────────────────────────────────────────────────────────────────

/** A principal the host's superuser before answers for. */
class ScopedRootUser extends User
{
    public function getMorphClass()
    {
        return 'user';
    }
}

/** A subject that is no model: nothing to derive a name from. */
class ScopedReport {}

class ScopedReportPolicy
{
    public function view(User $user, ScopedReport $report): bool
    {
        return true;
    }

    public function destroy(User $user, ScopedReport $report): bool
    {
        return false;
    }
}

class ScopedGadget extends Model
{
    protected $table = 'widgets';

    protected $guarded = [];

    public function getMorphClass()
    {
        return 'scoped-gadget';
    }
}

/** Outside the cascade: `view` is a membership arm (asks no permission), `update` an ownership arm, `approve` asks one. */
class ScopedGadgetPolicy
{
    public function view(User $user, ScopedGadget $gadget): bool
    {
        return (int) $gadget->user_id === (int) $user->id;
    }

    public function update(User $user, ScopedGadget $gadget): bool
    {
        return (int) $gadget->user_id === (int) $user->id;
    }

    public function approve(User $user, ScopedGadget $gadget): bool
    {
        return $user->can('widgets.approve');
    }
}

/** Overrides `view` the way tower ConduitPolicy does: any authenticated user, no rung checked. */
class ScopedOpenPostPolicy extends PostPolicy
{
    public function view(?Illuminate\Contracts\Auth\Authenticatable $user, Model $instance)
    {
        return $user !== null;
    }
}

/** Guards `view`, then runs the cascade's rungs, and declares their names (as tower ThreadPolicy does). */
class ScopedGuardedPostPolicy extends PostPolicy
{
    public function view(?Illuminate\Contracts\Auth\Authenticatable $user, Model $instance)
    {
        return $instance->name !== 'guarded' && parent::view($user, $instance);
    }

    public function decisionNames(string $ability, array $arguments): ?array
    {
        return $ability === 'view' ? $this->cascadeRungNames($ability, $arguments) : parent::decisionNames($ability, $arguments);
    }
}

/** Replaces a configured verb (as beam-accounts InvitationPolicy replaces create and delete). */
class ScopedReplacedConfiguredPolicy extends ConfiguredModelPolicy
{
    public function create(Illuminate\Contracts\Auth\Authenticatable $user)
    {
        return true;
    }
}

/** A configured policy whose `view` is an unconditional override (#[UseCascadePolicy(view: true)]). */
class ScopedViewOverrideWidgetPolicy extends ConfiguredModelPolicy
{
    public function __construct()
    {
        parent::__construct(Widget::class, ['view' => true]);
    }
}
