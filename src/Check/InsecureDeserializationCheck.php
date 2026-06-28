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
use Symfony\Component\Finder\Finder;

final class InsecureDeserializationCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'Insecure Deserialization Audit';
    }

    public function getDescription(): string
    {
        return 'Scans for dangerous use of unserialize() on potentially untrusted input.';
    }

    public function run(): CheckResult
    {
        $srcPath = getcwd() . DIRECTORY_SEPARATOR . 'src';
        $finder  = new Finder();
        $finder->files()->in($srcPath)->name('*.php');

        $violations = [];

        foreach ($finder as $file) {
            $contents = $file->getContents();
            $tokens   = token_get_all($contents);
            $filePath = $file->getRelativePathname();

            foreach ($tokens as $index => $token) {
                if (is_array($token) && $token[0] === T_STRING && strtolower($token[1]) === 'unserialize') {
                    // We found an unserialize call.
                    // Now, we verify if it is likely acting on user input.
                    // This is a heuristic: if we find references to common input sinks nearby.
                    $context = substr($contents, (int)$token[2], 200);

                    if (preg_match('/(\$this|\$_GET|\$_POST|\$_REQUEST|request->get|query->get)/i', $context)) {
                        $violations[] = sprintf(
                            'Potential insecure use of unserialize() detected in %s on line %d. Avoid unserializing user-controlled input.',
                            $filePath,
                            $token[2]
                        );
                    }
                }
            }
        }

        if (!empty($violations)) {
            return $this->fail(
                $violations,
                'Remediation: Never unserialize user-controlled data. Use JSON (json_decode) for data interchange, which does not instantiate objects.'
            );
        }

        return $this->pass(['No obvious insecure deserialization patterns detected.']);
    }
}
