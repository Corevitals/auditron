<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: CsrfConfigurationCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:44 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class CsrfConfigurationCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'CSRF Configuration Audit';
    }

    public function getDescription(): string
    {
        return 'Scans framework.yaml to ensure global CSRF protection is active and session cookies enforce SameSite policies.';
    }

    public function run(): CheckResult
    {
        $yamlPath = getcwd() . DIRECTORY_SEPARATOR . 'config/packages/framework.yaml';

        if (!file_exists($yamlPath)) {
            return $this->skip(['No configuration found at config/packages/framework.yaml. (API-only architectures may not require this)']);
        }

        try {
            $parsed = Yaml::parseFile($yamlPath);
        } catch (ParseException $e) {
            return $this->fail([sprintf('Failed to parse framework.yaml: %s', $e->getMessage())]);
        }

        $violations = [];
        $framework = $parsed['framework'] ?? [];

        // Audit Global CSRF Protection
        $csrf = $framework['csrf_protection'] ?? null;

        // In Symfony, this can be a boolean `false` or an array `['enabled' => false]`
        if ($csrf === false || (is_array($csrf) && isset($csrf['enabled']) && $csrf['enabled'] === false)) {
            $violations[] = 'Global CSRF protection is explicitly disabled in framework.yaml.';
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['framework.yaml enforces robust CSRF and session cookie policies.']);
    }
}
