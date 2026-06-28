<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: FilePermissionsCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 4:15 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Finder\Finder;

final class FilePermissionsCheck extends AbstractCheck
{
    public function getName(): string
    {
        return 'File Permissions & ACL Audit';
    }

    public function getDescription(): string
    {
        return 'Scans critical project directories for highly insecure 0777 permissions and verifies environment files are not world-writable.';
    }

    public function run(): CheckResult
    {
        $projectRoot = getcwd();
        $violations  = [];

        // Audit Environment Files (Must never be world-writable)
        $envFiles = ['.env', '.env.local', '.env.test'];
        foreach ($envFiles as $file) {
            $path = $projectRoot . DIRECTORY_SEPARATOR . $file;

            if (file_exists($path)) {
                $perms = fileperms($path);

                // Bitwise check for the world-writable bit (0002)
                if ($perms !== false && ($perms & 0x0002)) {
                    $violations[] = sprintf(
                        'Critical file "%s" is world-writable (Permissions: %04o). This must be restricted to 0644 or 0640.',
                        $file,
                        $perms & 0777
                    );
                }
            }
        }

        // Audit Critical Directories for 0777
        $criticalDirs = ['src', 'config', 'public', 'var'];

        // Filter out directories that might not exist in the current environment
        $existingDirs = array_filter(
            $criticalDirs,
            fn($dir) => is_dir($projectRoot . DIRECTORY_SEPARATOR . $dir)
        );

        if (!empty($existingDirs)) {

            foreach ($existingDirs as $dir) {
                $path  = $projectRoot . DIRECTORY_SEPARATOR . $dir;
                $perms = fileperms($path);

                if ($perms !== false && ($perms & 0777) === 0777) {
                    $violations[] = sprintf(
                        'Directory "%s/" has completely open 0777 permissions. This is a severe security risk.',
                        $dir
                    );
                }
            }

            $finder = new Finder();
            // We limit depth to 2 to catch top-level var/cache or var/log modifications
            // without traversing millions of actual cache files.
            $finder->in($existingDirs)->depth('< 3');

            foreach ($finder as $item) {
                $perms = fileperms($item->getRealPath());

                // Bitwise check for exact 0777 (world readable, writable, and executable)
                if ($perms !== false && ($perms & 0777) === 0777) {
                    $type = $item->isDir() ? 'Directory' : 'File';
                    $violations[] = sprintf(
                        '%s "%s" has completely open 0777 permissions. This is a severe security risk.',
                        $type,
                        $item->getRelativePathname()
                    );
                }
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['Critical files and directories maintain secure permission boundaries.']);
    }
}
