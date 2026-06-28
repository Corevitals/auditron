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
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class InsecureFirewallCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'Security Configuration (security.yaml) Audit';
    }

    public function getDescription(): string
    {
        return 'Scans security.yaml for stateful APIs, disabled CSRF protection, and weak access controls.';
    }

    public function run(): CheckResult
    {
        $yamlPath = getcwd() . DIRECTORY_SEPARATOR . 'config/packages/security.yaml';

        if (!file_exists($yamlPath)) {
            return $this->skip(['No configuration found at config/packages/security.yaml.']);
        }

        try {
            $parsed = Yaml::parseFile($yamlPath);
        } catch (ParseException $e) {
            return $this->fail([sprintf('Failed to parse security.yaml: %s', $e->getMessage())]);
        }

        $violations = [];
        $security = $parsed['security'] ?? [];

        // 1. Audit Firewalls
        $firewalls = $security['firewalls'] ?? [];
        foreach ($firewalls as $name => $config) {
            if ($name === 'dev') {
                continue; // Standard dev firewall is ignored
            }

            // Verify API statelessness
            if (isset($config['pattern']) && str_contains($config['pattern'], '^/api')) {
                if (isset($config['stateless']) && $config['stateless'] === false) {
                    $violations[] = sprintf('Firewall "%s" governs API routes but is not strictly stateless (stateless: false).', $name);
                }
            }

            // Verify CSRF protection on form login
            if (isset($config['form_login'])) {
                if (isset($config['form_login']['enable_csrf']) && $config['form_login']['enable_csrf'] === false) {
                    $violations[] = sprintf('Firewall "%s" explicitly disables CSRF protection on form_login.', $name);
                }
            }
        }

        // 2. Audit Access Controls
        $accessControls = $security['access_control'] ?? [];
        foreach ($accessControls as $index => $ac) {
            $path = $ac['path'] ?? '';

            if ($path !== '') {
                // Verify strict regex boundaries
                if (!str_starts_with($path, '^')) {
                    $violations[] = sprintf(
                        'Access control rule #%d (path: "%s") lacks the ^ anchor, exposing unintended route matching.',
                        $index + 1,
                        $path
                    );
                }

                // Verify HTTPS enforcement on sensitive domains
                if (preg_match('/(profile|admin|account|billing|secure)/i', $path)) {
                    if (!isset($ac['requires_channel']) || $ac['requires_channel'] !== 'https') {
                        $violations[] = sprintf(
                            'Access control rule #%d (path: "%s") governs sensitive routes but does not enforce defense-in-depth (requires_channel: https).',
                            $index + 1,
                            $path
                        );
                    }
                }
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['security.yaml configuration passes strict baseline audits.']);
    }
}
