<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: SessionCookieFlagsCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 4:05 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class SessionCookieFlagsCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'Session Cookie Flags Audit';
    }

    public function getDescription(): string
    {
        return 'Scans framework.yaml to ensure session cookies enforce HttpOnly, Secure, and SameSite policies to mitigate XSS and CSRF.';
    }

    public function run(): CheckResult
    {
        $yamlPath = getcwd() . DIRECTORY_SEPARATOR . 'config/packages/framework.yaml';

        if (!file_exists($yamlPath)) {
            return $this->skip(['No configuration found at config/packages/framework.yaml.']);
        }

        try {
            $parsed = Yaml::parseFile($yamlPath);
        } catch (ParseException $e) {
            return $this->fail([sprintf('Failed to parse framework.yaml: %s', $e->getMessage())]);
        }

        $session = $parsed['framework']['session'] ?? null;

        if (!is_array($session)) {
            return $this->skip(['No explicit session configuration found. Assuming secure framework defaults.']);
        }

        $violations = [];
        $warnings = [];

        // Audit HttpOnly Flag (Mitigates XSS session theft)
        $httpOnly = $session['cookie_httponly'] ?? null;
        if ($httpOnly === false) {
            $violations[] = 'Session cookie_httponly is explicitly set to false, exposing the session to XSS attacks via JavaScript.';
        }

        // Audit Secure Flag (Mitigates unencrypted transmission)
        $secure = $session['cookie_secure'] ?? null;
        if ($secure === false) {
            $violations[] = 'Session cookie_secure is explicitly set to false, allowing the session cookie to be transmitted over unencrypted HTTP.';
        } elseif ($secure === 'auto') {
             $warnings[] = 'Session cookie_secure is set to "auto". Ensure your load balancer/proxy correctly forwards X-Forwarded-Proto headers to avoid silent downgrades.';
        }

        // Audit SameSite Policy (Mitigates CSRF)
        $sameSite = $session['cookie_samesite'] ?? null;
        if ($sameSite === null) {
            $violations[] = 'Session configuration does not explicitly define a cookie_samesite policy. Expected "lax" or "strict".';
        } else {
            $normalizedSameSite = strtolower((string) $sameSite);
            if (!in_array($normalizedSameSite, ['lax', 'strict', 'auto'], true)) {
                $violations[] = sprintf(
                    'Session cookie_samesite is set to "%s", which leaves the application vulnerable to cross-site requests.',
                    $sameSite
                );
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        if (!empty($warnings)) {
            return $this->warning($warnings);
        }

        return $this->pass(['Session cookie flags (HttpOnly, Secure, SameSite) are securely configured.']);
    }
}
