<?php

namespace Rushing\PermissionCascade\Tests\Fixtures;

/**
 * A host reach vocabulary expressed as a backed enum (as audiostud's Visibility is), used to
 * prove `HasVisibility` neither clobbers the host's enum cast nor leaks the enum into the
 * cascade's string tier contract.
 */
enum Reach: string
{
    case Private = 'private';
    case Unlisted = 'unlisted';
    case Public = 'public';
}
