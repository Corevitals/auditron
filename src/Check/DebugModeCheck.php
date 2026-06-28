<?php

/**
 * Check <<projectversion>>
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: DebugModeCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:32 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;

final class DebugModeCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'Production Environment & Debug Mode Check';
    }

    public function getDescription(): string
    {
        return 'Ensures that APP_ENV is not set to dev and APP_DEBUG is disabled in local environment files.';
    }

    public function run(): CheckResult
    {
        $projectRoot = getcwd();
        $envFiles = ['.env', '.env.local'];
        $violations = [];

        foreach ($envFiles as $file) {
            $filePath = $projectRoot . DIRECTORY_SEPARATOR . $file;

            if (!file_exists($filePath)) {
                continue;
            }

            $contents = file_get_contents($filePath);

            if ($contents === false) {
                $violations[] = sprintf('Unable to read %s to verify environment variables.', $file);
                continue;
            }

            // Check for explicit dev environment
            if (preg_match('/^APP_ENV=(dev|test)\b/m', $contents)) {
                $violations[] = sprintf('Found non-production APP_ENV in %s', $file);
            }

            // Check for debug mode being enabled
            if (preg_match('/^APP_DEBUG=(1|true)\b/i', $contents)) {
                $violations[] = sprintf('Found active APP_DEBUG in %s', $file);
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['No debug configurations found in environment files.']);
    }
}
