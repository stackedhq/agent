package executor

import (
	"log"
	"os"
	"path/filepath"
)

// ReconcileSecretPermissions tightens credential-bearing files left at
// 0644/0755 by older agents. Safe to call on every startup: missing
// trees are a no-op (fresh install / Setup not yet run).
func ReconcileSecretPermissions() error {
	tightenServiceSecrets(servicesDir)
	tightenDatabaseSecrets(databasesDir)
	tightenGateSecrets(filepath.Dir(gateConfigPath))
	return nil
}

func tightenServiceSecrets(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("secret-perms: list %s: %v", root, err)
		}
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		chmodSecretDir(dir)
		chmodSecretFile(filepath.Join(dir, ".env"))
	}
}

func tightenDatabaseSecrets(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("secret-perms: list %s: %v", root, err)
		}
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		chmodSecretDir(dir)
		chmodSecretFile(filepath.Join(dir, "docker-compose.yml"))
	}
}

func tightenGateSecrets(dir string) {
	if _, err := os.Stat(dir); err != nil {
		return
	}
	chmodSecretDir(dir)
	chmodSecretFile(filepath.Join(dir, "config.json"))
}

func chmodSecretDir(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("secret-perms: stat %s: %v", path, err)
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return
	}
	if info.Mode().Perm() == secretDirMode {
		return
	}
	if err := os.Chmod(path, secretDirMode); err != nil {
		log.Printf("secret-perms: chmod %s: %v", path, err)
	}
}

func chmodSecretFile(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("secret-perms: stat %s: %v", path, err)
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return
	}
	if info.Mode().Perm() == secretFileMode {
		return
	}
	if err := os.Chmod(path, secretFileMode); err != nil {
		log.Printf("secret-perms: chmod %s: %v", path, err)
	}
}
