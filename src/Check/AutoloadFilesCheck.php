<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: AutoloadFilesCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 4:44 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;

final class AutoloadFilesCheck extends AbstractCheck
{
    // Adjust these based on your project's specific "trusted" files
    private const WHITELIST = [
        'symfony/polyfill-*',
        'symfony/deprecation-contracts',
        'guzzlehttp/guzzle',
        'guzzlehttp/psr7',
        'guzzlehttp/promises',
        'ramsey/uuid',
        'ramsey/collection',
        'paragonie/random_compat',
        'paragonie/sodium_compat',
        'voku/portable-ascii',
        'composer/installers',
        'composer/semver',
        'swiftmailer/swiftmailer',
        'phpunit/php-timer',
        'phpunit/php-text-template',
        'webmozart/assert',
        'nesbot/carbon',
    ];

    public function getName(): string
    {
        return 'Composer Autoload Files Audit';
    }

    public function getDescription(): string
    {
        return 'Detects files registered in autoload.files that are not explicitly whitelisted, preventing unauthorized global execution of code.';
    }

    public function run(): CheckResult
    {
        $composerPath = getcwd() . DIRECTORY_SEPARATOR . 'composer.json';

        if (!file_exists($composerPath)) {
            return $this->skip(['composer.json not found in project root.']);
        }

        $composer = json_decode(file_get_contents($composerPath), true);

        // Extract files from both autoload and autoload-dev blocks
        $files = array_merge(
            $composer['autoload']['files'] ?? [],
            $composer['autoload-dev']['files'] ?? []
        );

        if (empty($files)) {
            return $this->pass(['No global autoload files detected in production or dev configurations.']);
        }

        $registeredFiles = $files;
        $unauthorized = [];

        foreach ($registeredFiles as $file) {
            if (!in_array($file, self::WHITELIST, true)) {
                $unauthorized[] = $file;
            }
        }

        if (!empty($unauthorized)) {
            return $this->fail(
                ['The following files are registered in autoload.files but are not in the whitelist: ' . implode(', ', $unauthorized)],
                'REMEDIATION: autoload.files executes globally on every request. Move logic to a class-based structure with PSR-4 autoloading. If this file is legitimate, add it to the WHITELIST in AutoloadFilesCheck.php.'
            );
        }

        return $this->pass(['All registered autoload files are within the security whitelist.']);
    }
}
