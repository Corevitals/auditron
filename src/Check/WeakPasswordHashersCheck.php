<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: WeakPasswordHashersCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:54 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class WeakPasswordHashersCheck extends AbstractCheck
{
    /**
     * A list of cryptographically broken or insecure hashing algorithms.
     */
    private const WEAK_ALGORITHMS = [
        'md5',
        'sha1',
        'plaintext',
    ];

    public function getName(): string
    {
        return 'Weak Password Hashers Audit';
    }

    public function getDescription(): string
    {
        return 'Scans security.yaml to ensure no deprecated or cryptographically weak password hashing algorithms are in use.';
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

        $hashers = $parsed['security']['password_hashers'] ?? [];

        if (empty($hashers)) {
            return $this->pass(['No password hashers are explicitly configured.']);
        }

        $violations = [];

        foreach ($hashers as $class => $config) {
            $algorithm = null;

            // Symfony allows hashers to be defined as a simple string or a detailed array
            if (is_string($config)) {
                $algorithm = strtolower($config);
            } elseif (is_array($config) && isset($config['algorithm'])) {
                $algorithm = strtolower((string) $config['algorithm']);
            }

            if ($algorithm !== null && in_array($algorithm, self::WEAK_ALGORITHMS, true)) {
                $violations[] = sprintf(
                    'The entity/interface "%s" is configured to use the weak hashing algorithm "%s". Expected "auto", "sodium", or "argon2id".',
                    $class,
                    $algorithm
                );
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['All configured password hashers use strong algorithms.']);
    }
}
