<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: ComposerSecurityCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:49 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Process\Process;

final class ComposerSecurityCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'Composer Dependency Vulnerability Audit';
    }

    public function getDescription(): string
    {
        return 'Scans composer.lock for packages with known security vulnerabilities (CVEs) using the native audit engine.';
    }

    public function run(): CheckResult
    {
        $projectRoot = getcwd();

        if (!file_exists($projectRoot . DIRECTORY_SEPARATOR . 'composer.lock')) {
            return $this->skip(['No composer.lock found. Dependency audit skipped.']);
        }

        // Execute Composer's native audit command enforcing the lock file and requesting JSON output.
        $process = new Process(['composer', 'audit', '--format=json', '--locked']);
        $process->setWorkingDirectory($projectRoot);

        // Timeout is set to 60 seconds to allow for potential network latency when fetching the advisory database.
        $process->setTimeout(60.0);
        $process->run();

        // Composer writes the JSON output to STDOUT even if vulnerabilities (exit code > 0) are found.
        $output = $process->getOutput();

        // If STDOUT is empty but the process failed, Composer likely encountered a fatal error (e.g., missing binary).
        if ($output === '' && !$process->isSuccessful()) {
            return $this->fail([
                'Failed to execute composer audit. Ensure Composer is available in the system path.',
                'Error: ' . $process->getErrorOutput()
            ]);
        }

        $decoded = json_decode($output, true);

        if (!is_array($decoded) || !array_key_exists('advisories', $decoded)) {
            return $this->fail([
                'Failed to parse Composer audit JSON output. The structure may be malformed or unexpected.'
            ]);
        }

        if (empty($decoded['advisories'])) {
            return $this->pass(['No known vulnerabilities found in Composer dependencies.']);
        }

        $violations = [];
        foreach ($decoded['advisories'] as $package => $advisories) {
            foreach ($advisories as $advisory) {
                $identifier = $advisory['cve'] ?? $advisory['advisoryId'] ?? 'Unknown ID';
                $title      = $advisory['title'] ?? 'No description provided.';
                $link       = $advisory['link'] ?? '';

                $message = sprintf('[%s] %s: %s', $package, $identifier, $title);
                if ($link !== '') {
                    $message .= sprintf(' (%s)', $link);
                }

                $violations[] = $message;
            }
        }

        return $this->fail($violations);
    }
}
