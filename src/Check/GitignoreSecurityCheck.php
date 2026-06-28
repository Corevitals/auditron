<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: GitignoreSecurityCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:59 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;

final class GitignoreSecurityCheck extends AbstractCheck
{
    /**
     * Maps the human-readable requirement to a regex pattern that matches
     * valid variations (e.g., handling optional leading/trailing slashes).
     */
    private const REQUIRED_IGNORES = [
        '.env.local'      => '^\s*\/?\.env\.local\s*$',
        '.env.*.local'    => '^\s*\/?\.env\.\*\.local\s*$',
        'vendor/'         => '^\s*\/?vendor\/?\s*$',
        'var/'            => '^\s*\/?var\/?\s*$',
        'phpunit results' => '^\s*\/?\.phpunit\.result\.cache\s*$',
    ];

    public function getName(): string
    {
        return 'Version Control (Git) Secrets Audit';
    }

    public function getDescription(): string
    {
        return 'Verifies that .gitignore is present and actively preventing sensitive environment files and directories from being committed.';
    }

    public function run(): CheckResult
    {
        $gitignorePath = getcwd() . DIRECTORY_SEPARATOR . '.gitignore';

        if (!file_exists($gitignorePath)) {
            return $this->fail([
                'No .gitignore file found in the project root.',
                'This poses a massive risk for accidentally committing sensitive files.'
            ]);
        }

        $contents = file_get_contents($gitignorePath);

        if ($contents === false) {
            return $this->fail(['Unable to read the contents of .gitignore.']);
        }

        $violations = [];

        foreach (self::REQUIRED_IGNORES as $name => $regex) {
            if (!preg_match('/' . $regex . '/m', $contents)) {
                $violations[] = sprintf('Missing strict ignore rule for "%s".', $name);
            }
        }

        // Additional heuristic: Look for exposed private keys
        if (!preg_match('/^\s*\*\.pem\s*$/m', $contents) && !preg_match('/^\s*\*\.key\s*$/m', $contents)) {
            // We issue this as a standard violation rather than a failure, as not all projects use local certs/keys,
            // but it is an enterprise best practice to proactively ignore them.
            $violations[] = 'Consider adding "*.pem" and "*.key" to .gitignore to prevent accidental SSL/JWT key exposure.';
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['.gitignore securely prevents the commitment of core sensitive files.']);
    }
}
