<?php

namespace Rushing\PermissionCascade\Contracts;

use Rushing\PermissionCascade\Policies\BaseModelPolicy;

/**
 * Marks a policy whose permission tokens are RESERVED: no derived, uniform role tiering may grant
 * them. Only a seeder or config entry that names the model explicitly grants its tokens to a role.
 *
 * A {@see BaseModelPolicy} answers from `{alias}.{verb}` tokens, and a consumer that derives role
 * grants from the Gate's policy map (beam-accounts' `RolePermissions` hands every policed model
 * `view` at member tier and `create`/`update`/`delete` at admin tier) would otherwise grant those
 * tokens to every team role at every host that installs the model's package. That is right for team
 * content and wrong for a platform-level model such as a commerce plan catalog or a tenant's
 * conduit credentials, where the owning package cannot know which of a host's roles should write.
 *
 * With this marker and no explicit grant, no role holds the tokens, so the only principal that can
 * pass is a host's `Gate::before` superuser (Root at the flagship). The marker is on the POLICY
 * class, beside the rule it qualifies; a model bound through `#[UseCascadePolicy]` has no class of
 * its own and is always derivable.
 *
 * It declares no methods. A consumer tests `is_a($policy, GrantedExplicitly::class, true)`.
 */
interface GrantedExplicitly {}
