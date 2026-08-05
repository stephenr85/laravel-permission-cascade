<?php

namespace Rushing\PermissionCascade\Tests;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Rushing\PermissionCascade\PermissionCascadeServiceProvider;
use Rushing\PermissionCascade\Tests\Fixtures\AccessGrant;
use Rushing\PermissionCascade\Tests\Fixtures\Gadget;
use Rushing\PermissionCascade\Tests\Fixtures\Post;
use Rushing\PermissionCascade\Tests\Fixtures\User;
use Rushing\PermissionCascade\Tests\Fixtures\Vault;
use Rushing\PermissionCascade\Tests\Fixtures\Widget;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Relation::enforceMorphMap([
            'user' => User::class,
            'widget' => Widget::class,
            'gadget' => Gadget::class,
            'vault' => Vault::class,
            'post' => Post::class,
            'role' => Role::class,
        ]);

        $this->createSpatieSchema();
        $this->createFixtureSchema();
    }

    protected function getPackageProviders($app): array
    {
        return [
            PermissionServiceProvider::class,
            PermissionCascadeServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('auth.providers.users.model', User::class);

        // Point the cascade's ownership traits at the fixture user.
        $app['config']->set('permission-cascade.user_model', User::class);
        $app['config']->set('permission-cascade.team_foreign_key', 'team_id');

        // The package ships no grant model; register the test host's model (Fixtures\AccessGrant)
        // so the explicit-grant rung resolves against a real table.
        $app['config']->set('permission-cascade.grant_model', AccessGrant::class);

        // Teams-mode is the package default; make it explicit for the schema below.
        $app['config']->set('permission.teams', true);
        $app['config']->set('permission.column_names.team_foreign_key', 'team_id');
    }

    protected function createFixtureSchema(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });

        Schema::create('widgets', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->timestamps();
        });

        Schema::create('gadgets', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->timestamps();
        });

        Schema::create('vaults', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->unsignedBigInteger('parent_id')->nullable();
            $table->string('visibility')->nullable();
            $table->timestamps();
        });

        Schema::create('posts', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('visibility')->nullable();
            $table->boolean('listed')->nullable();
            $table->timestamps();
        });

        Schema::create('grants', function (Blueprint $table): void {
            $table->id();
            $table->string('grantable_type');
            $table->unsignedBigInteger('grantable_id');
            $table->string('grantee_type');
            $table->unsignedBigInteger('grantee_id');
            $table->string('ability');
            $table->string('effect');
            $table->timestamps();
            $table->index(['grantable_type', 'grantable_id']);
            $table->index(['grantee_type', 'grantee_id']);
        });

        Schema::create('userables', function (Blueprint $table): void {
            $table->unsignedBigInteger('user_id');
            $table->string('userable_type');
            $table->unsignedBigInteger('userable_id');
        });
    }

    protected function createSpatieSchema(): void
    {
        Schema::create('permissions', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('guard_name');
            $table->timestamps();
            $table->unique(['name', 'guard_name']);
        });

        Schema::create('roles', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('team_id')->nullable();
            $table->string('name');
            $table->string('guard_name');
            $table->timestamps();
            $table->unique(['team_id', 'name', 'guard_name']);
        });

        Schema::create('model_has_permissions', function (Blueprint $table): void {
            $table->unsignedBigInteger('permission_id');
            $table->string('model_type');
            $table->unsignedBigInteger('model_id');
            $table->unsignedBigInteger('team_id');
            $table->index(['model_id', 'model_type']);
            $table->primary(['team_id', 'permission_id', 'model_id', 'model_type']);
        });

        Schema::create('model_has_roles', function (Blueprint $table): void {
            $table->unsignedBigInteger('role_id');
            $table->string('model_type');
            $table->unsignedBigInteger('model_id');
            $table->unsignedBigInteger('team_id');
            $table->index(['model_id', 'model_type']);
            $table->primary(['team_id', 'role_id', 'model_id', 'model_type']);
        });

        Schema::create('role_has_permissions', function (Blueprint $table): void {
            $table->unsignedBigInteger('permission_id');
            $table->unsignedBigInteger('role_id');
            $table->primary(['permission_id', 'role_id']);
        });
    }
}
