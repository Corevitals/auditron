<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: EnvVarSecurityCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 4:24 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;

final class EnvVarSecurityCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'Environment Variable Configuration Audit';
    }

    public function getDescription(): string
    {
        return 'Scans environment files (.env, .env.local) for insecure default values, compromised secrets, and wildcard CORS configurations.';
    }

    public function run(): CheckResult
    {
        $projectRoot = getcwd();
        $envFiles    = ['.env', '.env.local'];
        $violations  = [];

        foreach ($envFiles as $fileName) {
            $filePath = $projectRoot . DIRECTORY_SEPARATOR . $fileName;

            if (!file_exists($filePath)) {
                continue;
            }

            $contents = file_get_contents($filePath);

            if ($contents === false) {
                $violations[] = sprintf('Unable to read %s to verify variables.', $fileName);
                continue;
            }

            // Audit APP_SECRET for the Symfony default or empty strings
            if (preg_match('/^APP_SECRET=[\'"]?ThisTokenIsNotSoSecretChangeIt[\'"]?/m', $contents)
                || preg_match('/^APP_SECRET=[\'"]{0,2}$/m', $contents)
            ) {
                $violations[] = sprintf(
                    'Found default or empty APP_SECRET in %s. This must be a unique, cryptographically secure string.',
                    $fileName
                );
            }

            // Audit DATABASE_URL for dangerous default credentials (e.g., root:@, postgres:postgres@)
            if (preg_match('/^DATABASE_URL=.*:\/\/(root|admin|postgres):(root|admin|postgres|password)?@/im', $contents)
                || preg_match('/^DATABASE_URL=.*:\/\/(root|postgres)@/im', $contents)
            ) {
                $violations[] = sprintf(
                    'Found weak or default database credentials in %s. Do not use local defaults in committed configuration.',
                    $fileName
                );
            }

            // Audit CORS_ALLOW_ORIGIN for global wildcards
            if (preg_match('/^CORS_ALLOW_ORIGIN=[\'"]?\*[\'"]?/m', $contents)) {
                $violations[] = sprintf(
                    'Found wildcard CORS_ALLOW_ORIGIN (*) in %s. This permits any external domain to make cross-site requests to your API.',
                    $fileName
                );
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['Environment variables are free of known insecure defaults.']);
    }
}
