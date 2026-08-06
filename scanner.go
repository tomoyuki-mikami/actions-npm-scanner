package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

// PackageJSON represents a package.json file
type PackageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	BundledDependencies  []string          `json:"bundledDependencies"`
}

// PackageLockJSON represents a package-lock.json file (v1-v3)
type PackageLockJSON struct {
	LockfileVersion int                               `json:"lockfileVersion,omitempty"`
	Packages        map[string]PackageLockPackageInfo `json:"packages,omitempty"`     // v2/v3
	Dependencies    map[string]PackageLockInfo        `json:"dependencies,omitempty"` // v1
}

// PackageLockPackageInfo represents package information in package-lock.json v2/v3 (flat structure)
type PackageLockPackageInfo struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved,omitempty"`     // Actual URL used to download the package
	Dependencies map[string]string `json:"dependencies,omitempty"` // v2/v3: dependencies are version strings
}

// PackageLockInfo represents package information in package-lock.json v1 (nested structure)
type PackageLockInfo struct {
	Version      string                     `json:"version"`
	Dependencies map[string]PackageLockInfo `json:"dependencies,omitempty"` // v1: dependencies are nested structures
}

// PnpmLock represents the structure of pnpm-lock.yaml
type PnpmLock struct {
	// LockfileVersion is written as a number (5.4) up to lockfile v5 and as a
	// quoted string ('9.0') from v6 onwards, so it is kept as a raw node to
	// avoid failing the whole file on a type mismatch.
	LockfileVersion yaml.Node                  `yaml:"lockfileVersion"`
	Dependencies    map[string]PnpmDependency  `yaml:"dependencies,omitempty"`
	DevDependencies map[string]PnpmDependency  `yaml:"devDependencies,omitempty"`
	Importers       map[string]PnpmImporter    `yaml:"importers,omitempty"` // v6+
	Packages        map[string]PnpmPackageInfo `yaml:"packages,omitempty"`
	Snapshots       map[string]PnpmPackageInfo `yaml:"snapshots,omitempty"` // v9+
	Specifiers      map[string]string          `yaml:"specifiers,omitempty"`
}

// PnpmImporter represents a workspace entry under the v6+ importers section
type PnpmImporter struct {
	Dependencies         map[string]PnpmDependency `yaml:"dependencies,omitempty"`
	DevDependencies      map[string]PnpmDependency `yaml:"devDependencies,omitempty"`
	OptionalDependencies map[string]PnpmDependency `yaml:"optionalDependencies,omitempty"`
}

// PnpmDependency represents a dependency entry in pnpm-lock.yaml.
// Lockfiles up to v5 store a bare version string, while v6+ importers store a
// mapping with `specifier` and `version` keys.
type PnpmDependency struct {
	Specifier string
	Version   string
}

// UnmarshalYAML accepts both the scalar and the mapping form of a dependency entry.
func (dependency *PnpmDependency) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		dependency.Version = value.Value
		return nil
	}

	var mapped struct {
		Specifier string `yaml:"specifier"`
		Version   string `yaml:"version"`
	}
	if err := value.Decode(&mapped); err != nil {
		return err
	}
	dependency.Specifier = mapped.Specifier
	dependency.Version = mapped.Version
	return nil
}

// PnpmPackageInfo represents package information in pnpm-lock.yaml
type PnpmPackageInfo struct {
	Resolution   interface{}       `yaml:"resolution,omitempty"`
	Version      string            `yaml:"version,omitempty"`
	Dev          bool              `yaml:"dev,omitempty"`
	Dependencies map[string]string `yaml:"dependencies,omitempty"`
}

// extractVersionFromResolved extracts version from resolved URL
// Example: "https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz" -> "4.1.1"
func extractVersionFromResolved(resolved string) string {
	if resolved == "" {
		return ""
	}

	// Look for pattern like "/-/packagename-version.tgz"
	parts := strings.Split(resolved, "/-/")
	if len(parts) < 2 {
		return ""
	}

	// Extract the filename part
	filename := parts[len(parts)-1]

	// Remove .tgz extension
	filename = strings.TrimSuffix(filename, ".tgz")

	// For packages like "react-18.0.0-beta.0", we need to find where the package name ends
	// and the version starts. Package names don't typically start with numbers.

	// Split by dashes and find the first part that starts with a digit (likely the version)
	dashParts := strings.Split(filename, "-")
	if len(dashParts) < 2 {
		return ""
	}

	// Find the index where version starts (first part starting with digit)
	versionStartIdx := -1
	for i := 1; i < len(dashParts); i++ { // Skip first part (package name)
		if len(dashParts[i]) > 0 && (dashParts[i][0] >= '0' && dashParts[i][0] <= '9') {
			versionStartIdx = i
			break
		}
	}

	if versionStartIdx == -1 {
		return ""
	}

	// Join the version parts back together
	version := strings.Join(dashParts[versionStartIdx:], "-")
	return version
}

// getActualVersion returns the most accurate version available
// Prioritizes resolved version over declared version
func getActualVersion(declared, resolved string) string {
	if resolvedVersion := extractVersionFromResolved(resolved); resolvedVersion != "" {
		return resolvedVersion
	}
	return declared
}

// VulnerablePackageMap provides optimized lookups for vulnerable packages
type VulnerablePackageMap map[string]VulnerablePackage

// buildVulnerablePackageMap creates a hashmap for O(1) package lookups
func buildVulnerablePackageMap(vulnerablePackages []VulnerablePackage) VulnerablePackageMap {
	packageMap := make(VulnerablePackageMap, len(vulnerablePackages))
	for _, pkg := range vulnerablePackages {
		packageMap[pkg.Name] = pkg
	}
	return packageMap
}

func buildVulnerablePypiPackageMap(vulnerablePackages []VulnerablePackage) VulnerablePackageMap {
	packageMap := make(VulnerablePackageMap, len(vulnerablePackages))
	for _, pkg := range vulnerablePackages {
		packageMap[canonicalPythonPackageName(pkg.Name)] = pkg
	}
	return packageMap
}

// isVulnerable checks if a package is vulnerable using the optimized map
func (vpm VulnerablePackageMap) isVulnerable(packageName, version string) (bool, VulnerablePackage) {
	if vulnerablePackage, exists := vpm[packageName]; exists {
		if isVersionVulnerable(version, vulnerablePackage.Versions) {
			return true, vulnerablePackage
		}
	}
	return false, VulnerablePackage{}
}

// formatVulnerabilityMessage formats a vulnerability message
func formatVulnerabilityMessage(pkgName, version, filename string, vulnerablePackage VulnerablePackage) string {
	return fmt.Sprintf("Found vulnerable package %s with version %s in %s", pkgName, version, filename)
}

// actionScanResult holds the findings for a directory together with the files
// that could not be scanned, so that one unreadable dependency file does not
// discard the findings of the other files in the same directory.
type actionScanResult struct {
	Vulnerabilities []string
	FileErrors      []string
}

func (result *actionScanResult) merge(vulnerabilities []string, fileErrors []string) {
	result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilities...)
	result.FileErrors = append(result.FileErrors, fileErrors...)
}

// ScanAction scans a downloaded action for vulnerable packages.
// Findings from the files that could be read are returned even when other
// dependency files in the same directory failed to parse; the returned error
// then describes those failures.
func ScanAction(actionDir string, catalog VulnerabilityCatalog) ([]string, error) {
	result := scanAction(actionDir, catalog, true)
	if len(result.FileErrors) > 0 {
		return result.Vulnerabilities, errors.New(strings.Join(result.FileErrors, "; "))
	}
	return result.Vulnerabilities, nil
}

func scanAction(actionDir string, catalog VulnerabilityCatalog, verbose bool) actionScanResult {
	var result actionScanResult

	// Build optimized vulnerability map once
	vulnerablePackageMap := buildVulnerablePackageMap(catalog.NpmPackages)
	pypiPackageMap := buildVulnerablePypiPackageMap(catalog.PypiPackages)

	npmScanners := []struct {
		filename string
		scan     func(string, VulnerablePackageMap) ([]string, error)
	}{
		{"package.json", scanPackageJSONOptimized},
		{"package-lock.json", scanPackageLockJSONOptimized},
		{"yarn.lock", scanYarnLockOptimized},
		{"pnpm-lock.yaml", scanPnpmLockOptimized},
		{bunLockfileName, scanBunLockOptimized},
	}

	// Whether bun.lock was both present and read successfully. Only then are its
	// dependencies actually covered, which is what decides how a bun.lockb next
	// to it is treated below.
	bunLockScanned := false

	for _, npmScanner := range npmScanners {
		path := filepath.Join(actionDir, npmScanner.filename)
		if _, err := os.Stat(path); err != nil {
			if verbose {
				fmt.Printf("       %s not found. Skipping.\n", npmScanner.filename)
			}
			continue
		}

		if verbose {
			fmt.Printf("    🔍 Scanning %s...\n", npmScanner.filename)
		}
		vulnerabilities, err := npmScanner.scan(path, vulnerablePackageMap)
		if err != nil {
			result.FileErrors = append(result.FileErrors, err.Error())
			if verbose {
				fmt.Fprintf(os.Stderr, "    Error scanning %s: %v\n", npmScanner.filename, err)
			}
			continue
		}
		if npmScanner.filename == bunLockfileName {
			bunLockScanned = true
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilities...)
	}

	result.merge(nil, scanBunBinaryLockfile(actionDir, bunLockScanned, verbose))

	pythonResult := scanPythonDependencyFiles(actionDir, pypiPackageMap, verbose)
	result.merge(pythonResult.Vulnerabilities, pythonResult.FileErrors)

	return result
}

// scanBunBinaryLockfile reports bun.lockb as an unreadable file instead of
// skipping it. The binary format is undocumented, so the lockfile is never
// parsed; staying silent about it would be indistinguishable from a clean scan
// of an action whose dependencies were never actually read.
//
// A bun.lockb next to a bun.lock that was read successfully is not reported:
// from Bun 1.2 onwards the text lockfile is the one Bun itself honours, so the
// dependencies were already scanned and the leftover binary file is not a
// coverage gap. A bun.lock that failed to parse suppresses nothing, because then
// no dependency of the action was read at all.
func scanBunBinaryLockfile(actionDir string, bunLockScanned bool, verbose bool) []string {
	path := filepath.Join(actionDir, bunBinaryLockfileName)
	if _, err := os.Stat(path); err != nil {
		if verbose {
			fmt.Printf("       %s not found. Skipping.\n", bunBinaryLockfileName)
		}
		return nil
	}

	if bunLockScanned {
		if verbose {
			fmt.Printf("       %s found alongside a scanned %s. Skipping the binary lockfile.\n", bunBinaryLockfileName, bunLockfileName)
		}
		return nil
	}

	err := bunBinaryLockfileError(path)
	if verbose {
		fmt.Fprintf(os.Stderr, "    Error scanning %s: %v\n", bunBinaryLockfileName, err)
	}
	return []string{err.Error()}
}

func scanDependencyFile(path string, vulnerablePackageMap, pypiPackageMap VulnerablePackageMap) ([]string, error) {
	filename := filepath.Base(path)
	if matched, err := filepath.Match("requirements*.txt", filename); err != nil {
		return nil, err
	} else if matched {
		return scanRequirementsTxt(path, pypiPackageMap)
	}

	switch filename {
	case "package.json":
		return scanPackageJSONOptimized(path, vulnerablePackageMap)
	case "package-lock.json":
		return scanPackageLockJSONOptimized(path, vulnerablePackageMap)
	case "yarn.lock":
		return scanYarnLockOptimized(path, vulnerablePackageMap)
	case "pnpm-lock.yaml":
		return scanPnpmLockOptimized(path, vulnerablePackageMap)
	case bunLockfileName:
		return scanBunLockOptimized(path, vulnerablePackageMap)
	case bunBinaryLockfileName:
		return nil, bunBinaryLockfileError(path)
	case "Pipfile.lock":
		return scanPipfileLock(path, pypiPackageMap)
	case "poetry.lock", "uv.lock":
		return scanPythonPackageLock(path, pypiPackageMap)
	default:
		return nil, fmt.Errorf("unsupported dependency file: %s", path)
	}
}

// Optimized scanning functions using VulnerablePackageMap

func scanPackageJSONOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageJSON PackageJSON
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Define all dependency types to check
	dependencyTypes := []struct {
		deps map[string]string
		name string
	}{
		{packageJSON.Dependencies, "dependencies"},
		{packageJSON.DevDependencies, "devDependencies"},
		{packageJSON.PeerDependencies, "peerDependencies"},
		{packageJSON.OptionalDependencies, "optionalDependencies"},
	}

	for _, depType := range dependencyTypes {
		if depType.deps == nil {
			continue
		}
		for pkgName, version := range depType.deps {
			if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, version); isVuln {
				baseMsg := formatVulnerabilityMessage(pkgName, version, filepath.Base(path), vulnerablePackage)
				msgWithType := fmt.Sprintf("%s (%s)", baseMsg, depType.name)
				foundVulnerabilities = append(foundVulnerabilities, msgWithType)
			}
		}
	}

	// Check bundledDependencies (array of package names without versions)
	for _, bundledPkg := range packageJSON.BundledDependencies {
		if _, exists := vulnerablePackageMap[bundledPkg]; exists {
			foundVulnerabilities = append(foundVulnerabilities, fmt.Sprintf("Found vulnerable package %s in %s (bundledDependencies) - version unknown, check manually", bundledPkg, filepath.Base(path)))
		}
	}

	return foundVulnerabilities, nil
}

func scanPythonDependencyFiles(actionDir string, vulnerablePackageMap VulnerablePackageMap, verbose bool) actionScanResult {
	var result actionScanResult

	recordError := func(filename string, err error) {
		result.FileErrors = append(result.FileErrors, err.Error())
		if verbose {
			fmt.Fprintf(os.Stderr, "    Error scanning %s: %v\n", filename, err)
		}
	}

	requirementsPaths, err := filepath.Glob(filepath.Join(actionDir, "requirements*.txt"))
	if err != nil {
		recordError("requirements*.txt", err)
	}
	if len(requirementsPaths) == 0 && verbose {
		fmt.Println("       requirements*.txt not found. Skipping.")
	}
	for _, path := range requirementsPaths {
		if verbose {
			fmt.Printf("    🔍 Scanning %s...\n", filepath.Base(path))
		}
		vulnerabilities, err := scanRequirementsTxt(path, vulnerablePackageMap)
		if err != nil {
			recordError(filepath.Base(path), err)
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilities...)
	}

	lockScanners := []struct {
		filename string
		scan     func(string, VulnerablePackageMap) ([]string, error)
	}{
		{"Pipfile.lock", scanPipfileLock},
		{"poetry.lock", scanPythonPackageLock},
		{"uv.lock", scanPythonPackageLock},
	}

	for _, lockScanner := range lockScanners {
		path := filepath.Join(actionDir, lockScanner.filename)
		if _, err := os.Stat(path); err != nil {
			if verbose {
				fmt.Printf("       %s not found. Skipping.\n", lockScanner.filename)
			}
			continue
		}

		if verbose {
			fmt.Printf("    🔍 Scanning %s...\n", lockScanner.filename)
		}
		vulnerabilities, err := lockScanner.scan(path, vulnerablePackageMap)
		if err != nil {
			recordError(lockScanner.filename, err)
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilities...)
	}

	return result
}

func scanRequirementsTxt(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		packageName, versionSpec := parseRequirementLine(line)
		if packageName == "" || versionSpec == "" {
			continue
		}
		if isVuln, vulnerablePackage := isPythonPackageSpecVulnerable(vulnerablePackageMap, packageName, versionSpec); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatPythonVulnerabilityMessage(packageName, versionSpec, filepath.Base(path), vulnerablePackage))
		}
	}

	return foundVulnerabilities, nil
}

func scanPipfileLock(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	type pipfilePackage struct {
		Version string `json:"version"`
	}
	var pipfileLock struct {
		Default map[string]pipfilePackage `json:"default"`
		Develop map[string]pipfilePackage `json:"develop"`
	}
	if err := json.Unmarshal(data, &pipfileLock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	sections := []map[string]pipfilePackage{pipfileLock.Default, pipfileLock.Develop}
	for _, section := range sections {
		for packageName, packageInfo := range section {
			if isVuln, vulnerablePackage := isPythonPackageSpecVulnerable(vulnerablePackageMap, packageName, packageInfo.Version); isVuln {
				foundVulnerabilities = append(foundVulnerabilities, formatPythonVulnerabilityMessage(packageName, packageInfo.Version, filepath.Base(path), vulnerablePackage))
			}
		}
	}

	return foundVulnerabilities, nil
}

func scanPythonPackageLock(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	flushPackage := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		if isVuln, vulnerablePackage := isPythonPackageSpecVulnerable(vulnerablePackageMap, name, version); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatPythonVulnerabilityMessage(name, version, filepath.Base(path), vulnerablePackage))
		}
	}

	var currentName, currentVersion string
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "[[package]]" {
			flushPackage(currentName, currentVersion)
			currentName = ""
			currentVersion = ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			currentName = trimQuotedValue(strings.TrimSpace(strings.TrimPrefix(line, "name = ")))
			continue
		}
		if strings.HasPrefix(line, "version = ") {
			currentVersion = trimQuotedValue(strings.TrimSpace(strings.TrimPrefix(line, "version = ")))
		}
	}
	flushPackage(currentName, currentVersion)

	return foundVulnerabilities, nil
}

func parseRequirementLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "git+") || strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		return "", ""
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	operators := []string{"===", "==", "!=", ">=", "<=", "~=", ">", "<"}
	operatorIndex := -1
	for _, operator := range operators {
		if idx := strings.Index(line, operator); idx >= 0 && (operatorIndex == -1 || idx < operatorIndex) {
			operatorIndex = idx
		}
	}
	if operatorIndex == -1 {
		return canonicalPythonPackageName(line), ""
	}

	return canonicalPythonPackageName(line[:operatorIndex]), strings.TrimSpace(line[operatorIndex:])
}

func isPythonPackageSpecVulnerable(packageMap VulnerablePackageMap, packageName, versionSpec string) (bool, VulnerablePackage) {
	canonicalName := canonicalPythonPackageName(packageName)
	vulnerablePackage, exists := packageMap[canonicalName]
	if !exists {
		return false, VulnerablePackage{}
	}
	if isPythonVersionSpecVulnerable(versionSpec, vulnerablePackage.Versions) {
		return true, vulnerablePackage
	}
	return false, VulnerablePackage{}
}

func isPythonVersionSpecVulnerable(versionSpec string, vulnerableVersions []string) bool {
	versionSpec = strings.TrimSpace(trimQuotedValue(versionSpec))
	if versionSpec == "" {
		return false
	}
	for _, vulnerableVersion := range vulnerableVersions {
		if pythonVersionSatisfiesSpec(vulnerableVersion, versionSpec) {
			return true
		}
	}
	return false
}

func pythonVersionSatisfiesSpec(version, versionSpec string) bool {
	constraints := strings.Split(versionSpec, ",")
	for _, constraint := range constraints {
		constraint = strings.TrimSpace(constraint)
		if constraint == "" {
			continue
		}
		if !pythonVersionSatisfiesConstraint(version, constraint) {
			return false
		}
	}
	return true
}

func pythonVersionSatisfiesConstraint(version, constraint string) bool {
	operators := []string{"===", "==", "!=", ">=", "<=", "~=", ">", "<"}
	operator := ""
	operand := constraint
	for _, candidate := range operators {
		if strings.HasPrefix(constraint, candidate) {
			operator = candidate
			operand = strings.TrimSpace(strings.TrimPrefix(constraint, candidate))
			break
		}
	}

	if operator == "" {
		return version == strings.TrimSpace(operand)
	}
	if operator == "==" || operator == "===" {
		return pythonVersionEquals(version, operand)
	}
	if operator == "!=" {
		return !pythonVersionEquals(version, operand)
	}
	if operator == "~=" {
		return pythonVersionCompatible(version, operand)
	}

	cmp, ok := comparePythonVersions(version, operand)
	if !ok {
		return false
	}
	switch operator {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	default:
		return false
	}
}

func pythonVersionEquals(version, operand string) bool {
	operand = strings.TrimSpace(operand)
	if strings.HasSuffix(operand, ".*") {
		return strings.HasPrefix(version, strings.TrimSuffix(operand, "*"))
	}
	return version == operand
}

func pythonVersionCompatible(version, operand string) bool {
	if cmp, ok := comparePythonVersions(version, operand); !ok || cmp < 0 {
		return false
	}
	upperBound := pythonCompatibleUpperBound(operand)
	if upperBound == "" {
		return false
	}
	cmp, ok := comparePythonVersions(version, upperBound)
	return ok && cmp < 0
}

func pythonCompatibleUpperBound(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return ""
	}
	if len(parts) == 2 {
		nextMajor, ok := incrementNumericString(parts[0])
		if !ok {
			return ""
		}
		return nextMajor + ".0.0"
	}
	nextMinor, ok := incrementNumericString(parts[1])
	if !ok {
		return ""
	}
	return parts[0] + "." + nextMinor + ".0"
}

func comparePythonVersions(left, right string) (int, bool) {
	leftVersion, err := semver.NewVersion(cleanPythonVersion(left))
	if err != nil {
		return 0, false
	}
	rightVersion, err := semver.NewVersion(cleanPythonVersion(right))
	if err != nil {
		return 0, false
	}
	return leftVersion.Compare(rightVersion), true
}

func cleanPythonVersion(version string) string {
	version = strings.TrimSpace(trimQuotedValue(version))
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimSuffix(version, ".*")
	return version
}

func canonicalPythonPackageName(name string) string {
	name = strings.TrimSpace(name)
	if idx := strings.Index(name, "["); idx >= 0 {
		name = name[:idx]
	}
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return strings.TrimSpace(name)
}

func trimQuotedValue(value string) string {
	return strings.Trim(strings.TrimSpace(value), "\"'")
}

func incrementNumericString(value string) (string, bool) {
	version, err := semver.NewVersion(value + ".0.0")
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%d", version.Major()+1), true
}

func formatPythonVulnerabilityMessage(pkgName, versionSpec, filename string, vulnerablePackage VulnerablePackage) string {
	return fmt.Sprintf("Found vulnerable package %s with version spec %s in %s (potential match)", pkgName, versionSpec, filename)
}

func scanPackageJSON(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageJSON PackageJSON
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Define all dependency types to check
	dependencyTypes := []struct {
		deps map[string]string
		name string
	}{
		{packageJSON.Dependencies, "dependencies"},
		{packageJSON.DevDependencies, "devDependencies"},
		{packageJSON.PeerDependencies, "peerDependencies"},
		{packageJSON.OptionalDependencies, "optionalDependencies"},
	}

	for _, vulnerablePackage := range vulnerablePackages {
		// Check all dependency types
		for _, depType := range dependencyTypes {
			if depType.deps == nil {
				continue
			}
			if version, ok := depType.deps[vulnerablePackage.Name]; ok {
				if isVersionVulnerable(version, vulnerablePackage.Versions) {
					baseMsg := formatVulnerabilityMessage(vulnerablePackage.Name, version, filepath.Base(path), vulnerablePackage)
					msgWithType := fmt.Sprintf("%s (%s)", baseMsg, depType.name)
					foundVulnerabilities = append(foundVulnerabilities, msgWithType)
				}
			}
		}

		// Check bundledDependencies (array of package names without versions)
		for _, bundledPkg := range packageJSON.BundledDependencies {
			if bundledPkg == vulnerablePackage.Name {
				foundVulnerabilities = append(foundVulnerabilities, fmt.Sprintf("Found vulnerable package %s in %s (bundledDependencies) - version unknown, check manually", vulnerablePackage.Name, filepath.Base(path)))
			}
		}
	}

	return foundVulnerabilities, nil
}

// isVersionVulnerable checks if the installed version range could include any vulnerable versions
// Supports semantic versioning ranges, exact matches, and prerelease versions
func isVersionVulnerable(installedVersion string, vulnerableVersions []string) bool {
	// First try exact string match for non-semver cases
	for _, vulnVersion := range vulnerableVersions {
		if installedVersion == vulnVersion {
			return true
		}
	}

	// Try to parse installed version as a constraint (e.g., "^4.1.0", "~4.1.0", ">=4.1.0")
	// But skip if it's just a plain version number
	if isConstraintNotVersion(installedVersion) {
		if installedConstraint, err := semver.NewConstraint(installedVersion); err == nil {
			// Check if any vulnerable version satisfies the installed constraint
			for _, vulnVersion := range vulnerableVersions {
				// Try parsing vulnerable version as exact version first
				if vulnVer, err := semver.NewVersion(vulnVersion); err == nil {
					if installedConstraint.Check(vulnVer) {
						return true
					}
				}
			}
			return false // If we successfully parsed as constraint, don't continue to exact version parsing
		}
	}

	// If installed version is not a constraint, try parsing as exact version
	cleanVersion := cleanVersionString(installedVersion)
	if installedVer, err := semver.NewVersion(cleanVersion); err == nil {
		for _, vulnVersion := range vulnerableVersions {
			// Try parsing vulnerable version as constraint first (e.g., ">=4.1.1 <4.2.0")
			if constraint, err := semver.NewConstraint(vulnVersion); err == nil {
				if constraint.Check(installedVer) {
					return true
				}
				continue // If it parsed as constraint, don't try as version
			}
			// Try parsing vulnerable version as exact version for exact matches
			if vulnVer, err := semver.NewVersion(vulnVersion); err == nil {
				// Check for exact version match
				if installedVer.Equal(vulnVer) {
					return true
				}
				// Check for prerelease vulnerability: if installed version has same core version
				// but is a prerelease of a vulnerable version
				if installedVer.Prerelease() != "" && vulnVer.Prerelease() == "" {
					coreInstalled, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", installedVer.Major(), installedVer.Minor(), installedVer.Patch()))
					if err == nil && coreInstalled.Equal(vulnVer) {
						return true // Prerelease of vulnerable version is considered vulnerable
					}
				}
			}
		}
	} else {
		// If parsing as semver failed, check if it's because of different format
		// Try direct string parsing without cleaning first
		if directVer, err := semver.NewVersion(installedVersion); err == nil {
			for _, vulnVersion := range vulnerableVersions {
				if vulnVer, err := semver.NewVersion(vulnVersion); err == nil {
					// Check for exact version match
					if directVer.Equal(vulnVer) {
						return true
					}
					// Check for prerelease vulnerability
					if directVer.Prerelease() != "" && vulnVer.Prerelease() == "" {
						coreInstalled, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", directVer.Major(), directVer.Minor(), directVer.Patch()))
						if err == nil && coreInstalled.Equal(vulnVer) {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// cleanVersionString removes version range indicators to get the actual version number
// Preserves prerelease and build metadata
func cleanVersionString(version string) string {
	version = strings.TrimSpace(version)
	// Remove common prefixes only from the beginning
	for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(version, prefix) {
			version = strings.TrimSpace(version[len(prefix):])
			break // Only remove one prefix
		}
	}
	return version
}

// isConstraintNotVersion checks if a string is a constraint (not just a version number)
func isConstraintNotVersion(version string) bool {
	version = strings.TrimSpace(version)
	// Check for constraint operators
	constraintPrefixes := []string{"^", "~", ">=", "<=", ">", "<", "="}
	for _, prefix := range constraintPrefixes {
		if strings.HasPrefix(version, prefix) {
			return true
		}
	}
	// Check for range (space indicates multiple constraints)
	if strings.Contains(version, " ") {
		return true
	}
	// Check for comma-separated constraints
	if strings.Contains(version, ",") {
		return true
	}
	return false
}

func scanYarnLockOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var currentPackageName string

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Package definition line (doesn't start with space and ends with :)
		if !strings.HasPrefix(lines[i], " ") && strings.HasSuffix(line, ":") {
			packageDef := strings.TrimSuffix(line, ":")

			// Handle multiple package specs separated by comma
			packageSpecs := strings.Split(packageDef, ",")

			for _, spec := range packageSpecs {
				spec = strings.TrimSpace(spec)
				spec = strings.Trim(spec, "\"'")

				// Extract package name from spec like "@ctrl/tinycolor@^4.1.0"
				packageName := extractPackageNameFromYarnSpec(spec)
				if packageName != "" {
					currentPackageName = packageName
					break // Use the first valid package name
				}
			}
		} else if strings.HasPrefix(lines[i], "  ") && strings.Contains(line, "version") {
			// Version line with proper indentation
			parts := strings.SplitN(line, "version", 2)
			if len(parts) == 2 {
				version := strings.TrimSpace(parts[1])
				version = strings.Trim(version, "\"'")

				// Check against vulnerable packages
				if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(currentPackageName, version); isVuln {
					foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(currentPackageName, version, filepath.Base(path), vulnerablePackage))
				}
			}
		}
	}

	return foundVulnerabilities, nil
}

func scanYarnLock(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var currentPackageName string

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Package definition line (doesn't start with space and ends with :)
		if !strings.HasPrefix(lines[i], " ") && strings.HasSuffix(line, ":") {
			packageDef := strings.TrimSuffix(line, ":")

			// Handle multiple package specs separated by comma
			packageSpecs := strings.Split(packageDef, ",")

			for _, spec := range packageSpecs {
				spec = strings.TrimSpace(spec)
				spec = strings.Trim(spec, "\"'")

				// Extract package name from spec like "@ctrl/tinycolor@^4.1.0"
				packageName := extractPackageNameFromYarnSpec(spec)
				if packageName != "" {
					currentPackageName = packageName
					break // Use the first valid package name
				}
			}
		} else if strings.HasPrefix(lines[i], "  ") && strings.Contains(line, "version") {
			// Version line with proper indentation
			parts := strings.SplitN(line, "version", 2)
			if len(parts) == 2 {
				version := strings.TrimSpace(parts[1])
				version = strings.Trim(version, "\"'")

				// Check against vulnerable packages
				for _, vulnerablePackage := range vulnerablePackages {
					if currentPackageName == vulnerablePackage.Name {
						if isVersionVulnerable(version, vulnerablePackage.Versions) {
							foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, version, filepath.Base(path), vulnerablePackage))
						}
					}
				}
			}
		}
	}

	return foundVulnerabilities, nil
}

// extractPackageNameFromYarnSpec extracts package name from yarn.lock package spec
// Examples:
//
//	"@ctrl/tinycolor@^4.1.0" -> "@ctrl/tinycolor"
//	"lodash@^4.17.21" -> "lodash"
//	"@babel/core@^7.12.3, @babel/core@^7.12.9" -> "@babel/core"
func extractPackageNameFromYarnSpec(spec string) string {
	spec = strings.TrimSpace(spec)

	// Handle scoped packages (@org/package@version)
	if strings.HasPrefix(spec, "@") {
		// Find the second @ which indicates the version separator
		firstSlash := strings.Index(spec, "/")
		if firstSlash == -1 {
			return ""
		}

		secondAt := strings.Index(spec[firstSlash:], "@")
		if secondAt == -1 {
			// No version spec, entire string is package name
			return spec
		}

		return spec[:firstSlash+secondAt]
	} else {
		// Regular package (package@version)
		atIndex := strings.Index(spec, "@")
		if atIndex == -1 {
			// No version spec
			return spec
		}
		return spec[:atIndex]
	}
}

func scanPnpmLockOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	entries, err := readPnpmLockEntries(path)
	if err != nil {
		return nil, err
	}

	var foundVulnerabilities []string
	for _, entry := range entries {
		if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(entry.name, entry.version); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(entry.name, entry.version, filepath.Base(path), vulnerablePackage))
		}
	}

	return foundVulnerabilities, nil
}

func scanPnpmLock(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	entries, err := readPnpmLockEntries(path)
	if err != nil {
		return nil, err
	}

	var foundVulnerabilities []string
	for _, entry := range entries {
		for _, vulnerablePackage := range vulnerablePackages {
			if entry.name == vulnerablePackage.Name && isVersionVulnerable(entry.version, vulnerablePackage.Versions) {
				foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, entry.version, filepath.Base(path), vulnerablePackage))
			}
		}
	}

	return foundVulnerabilities, nil
}

// pnpmPackageEntry is a package name/version pair resolved from a pnpm lockfile
type pnpmPackageEntry struct {
	name    string
	version string
}

func readPnpmLockEntries(path string) ([]pnpmPackageEntry, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var pnpmLock PnpmLock
	if err := yaml.Unmarshal(data, &pnpmLock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	return collectPnpmPackageEntries(pnpmLock), nil
}

// collectPnpmPackageEntries gathers every package name/version pair a pnpm
// lockfile refers to, covering lockfile v5 (path-style keys and top-level
// dependencies) through v9 (name@version keys, importers and snapshots).
// Duplicates across sections are reported only once.
func collectPnpmPackageEntries(pnpmLock PnpmLock) []pnpmPackageEntry {
	var entries []pnpmPackageEntry
	seen := make(map[pnpmPackageEntry]bool)

	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		entry := pnpmPackageEntry{name: name, version: version}
		if seen[entry] {
			return
		}
		seen[entry] = true
		entries = append(entries, entry)
	}

	for _, section := range []map[string]PnpmPackageInfo{pnpmLock.Packages, pnpmLock.Snapshots} {
		for pkgPath := range section {
			add(extractPackageNameAndVersionFromPnpmPath(pkgPath))
		}
	}

	addDependencies := func(dependencies map[string]PnpmDependency) {
		for pkgName, dependency := range dependencies {
			add(pkgName, cleanPnpmVersion(dependency.Version))
		}
	}

	addDependencies(pnpmLock.Dependencies)
	addDependencies(pnpmLock.DevDependencies)
	for _, importer := range pnpmLock.Importers {
		addDependencies(importer.Dependencies)
		addDependencies(importer.DevDependencies)
		addDependencies(importer.OptionalDependencies)
	}

	return entries
}

// extractPackageNameAndVersionFromPnpmPath extracts package name and version from a pnpm lockfile package key
// Examples:
//
//	"/@ctrl/tinycolor/4.1.1"        (lockfile v5) -> "@ctrl/tinycolor", "4.1.1"
//	"/@ctrl/tinycolor@4.1.1"        (v6 - v8)     -> "@ctrl/tinycolor", "4.1.1"
//	"@ctrl/tinycolor@4.1.1"         (v9)          -> "@ctrl/tinycolor", "4.1.1"
//	"/vue-loader@17.0.0(vue@3.0.0)"               -> "vue-loader", "17.0.0"
//	"/@scope/7zip-bin@5.2.0"                      -> "@scope/7zip-bin", "5.2.0"
func extractPackageNameAndVersionFromPnpmPath(pkgPath string) (string, string) {
	pkgPath = strings.TrimPrefix(pkgPath, "/")
	if pkgPath == "" {
		return "", ""
	}

	// Drop the peer dependency suffix first so the "@" inside it (for example
	// "(vue@3.0.0)") is not mistaken for the name/version separator.
	if index := strings.IndexByte(pkgPath, '('); index >= 0 {
		pkgPath = pkgPath[:index]
	}

	// Lockfile v5 and earlier separate name and version with "/".
	if index := strings.LastIndexByte(pkgPath, '/'); index > 0 {
		if version := cleanPnpmVersion(pkgPath[index+1:]); version != "" {
			return pkgPath[:index], version
		}
	}

	// Lockfile v6 and later use "name@version". A package name carries an "@"
	// only as the first character of its scope, so the next "@" is the
	// separator; searching from the end would split a key that still has an
	// underscore peer suffix ("17.0.0_vue@2.6.14") at the peer dependency.
	if index := strings.IndexByte(pkgPath[1:], '@'); index >= 0 {
		index++
		if version := cleanPnpmVersion(pkgPath[index+1:]); version != "" {
			return pkgPath[:index], version
		}
	}

	return "", ""
}

// cleanPnpmVersion strips the peer dependency suffix pnpm appends to resolved
// versions ("4.1.1(vue@3.0.0)" in v6+, "15.9.8_vue@2.6.14" in v5) and rejects
// non-registry references such as "link:../shared" or "npm:other@1.0.0".
func cleanPnpmVersion(version string) string {
	if index := strings.IndexByte(version, '('); index >= 0 {
		version = version[:index]
	}
	if index := strings.IndexByte(version, '_'); index >= 0 {
		version = version[:index]
	}

	version = strings.TrimSpace(version)
	if version == "" || version[0] < '0' || version[0] > '9' {
		return ""
	}
	// A resolved version never contains "@" or "/". Rejecting them keeps the
	// "/" split from claiming a v6+ key whose package name starts with a digit
	// ("@scope/7zip-bin@5.2.0"), so the "name@version" split gets to handle it.
	if strings.ContainsAny(version, "@/") {
		return ""
	}
	return version
}

const (
	// bunLockfileName is the text lockfile Bun writes by default since 1.2.
	bunLockfileName = "bun.lock"
	// bunBinaryLockfileName is Bun's older binary lockfile.
	bunBinaryLockfileName = "bun.lockb"
	// maxKnownBunLockfileVersion is the highest bun.lock "lockfileVersion" this
	// scanner has been checked against; Bun 1.3 writes 1. A lower number is an
	// older lockfile and still readable, but a higher one may lay out "packages"
	// in a way this parser cannot see, and decoding it anyway would report an
	// action as clean while none of its dependencies were understood.
	maxKnownBunLockfileVersion = 1
)

// BunLock represents the structure of bun.lock.
//
// Every value in "packages" is an array whose shape depends on how the
// dependency was resolved: a registry package is
// ["name@version", "<registry>", {metadata}, "<integrity>"], a git dependency
// carries the metadata object in second position, a tarball dependency has
// three elements and a workspace package only one. The first element is the
// only one that is always present and always a string, so the entries are kept
// as raw JSON and only that element is decoded.
type BunLock struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string][]json.RawMessage `json:"packages,omitempty"`
}

// bunBinaryLockfileError reports that bun.lockb was found but deliberately not
// parsed. The format is undocumented and carries no stability guarantee, so the
// scanner says so instead of letting the action look clean.
func bunBinaryLockfileError(path string) error {
	return fmt.Errorf("failed to scan %s: bun.lockb is Bun's binary lockfile and its format is undocumented, so it is not parsed; run \"bun install --save-text-lockfile\" to produce a bun.lock and scan that instead", path)
}

// stripJSONC removes comments and trailing commas from JSONC so that
// encoding/json can decode it. bun.lock is JSONC: Bun writes a trailing comma
// after the last entry of every object and accepts hand-written comments.
//
// The scan is string-aware. Comment markers only start a comment outside of a
// string literal, because bun.lock entries routinely embed "//" inside strings
// — a tarball dependency is recorded as
// "left-pad@https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", and a
// custom registry is stored as a URL as well. Cutting at the first "//" would
// truncate those strings and corrupt the document.
func stripJSONC(data []byte) []byte {
	stripped := make([]byte, 0, len(data))
	inString := false

	for i := 0; i < len(data); i++ {
		char := data[i]

		if inString {
			stripped = append(stripped, char)
			switch char {
			case '\\':
				// Copy the escaped byte verbatim so that an escaped quote does
				// not end the string.
				if i+1 < len(data) {
					i++
					stripped = append(stripped, data[i])
				}
			case '"':
				inString = false
			}
			continue
		}

		switch {
		case char == '"':
			inString = true
			stripped = append(stripped, char)
		case char == '/' && i+1 < len(data) && data[i+1] == '/':
			// Line comment: drop everything up to, but not including, the
			// newline so that the remaining line structure is preserved.
			for i+1 < len(data) && data[i+1] != '\n' {
				i++
			}
		case char == '/' && i+1 < len(data) && data[i+1] == '*':
			// Block comment: drop everything through the closing "*/", leaving a
			// space so that the tokens on either side stay separated. An
			// unterminated block comment consumes the rest of the input and is
			// left for encoding/json to report as invalid JSON.
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
			stripped = append(stripped, ' ')
		case char == '}' || char == ']':
			stripped = trimTrailingComma(stripped)
			stripped = append(stripped, char)
		default:
			stripped = append(stripped, char)
		}
	}

	return stripped
}

// trimTrailingComma removes a comma that only whitespace separates from the end
// of the output, which is what a trailing comma looks like once the closing
// brace or bracket is reached. A comma inside a string literal can never be in
// that position: the closing quote always follows it.
func trimTrailingComma(stripped []byte) []byte {
	end := len(stripped)
	for end > 0 && isJSONWhitespace(stripped[end-1]) {
		end--
	}
	if end > 0 && stripped[end-1] == ',' {
		return append(stripped[:end-1], stripped[end:]...)
	}
	return stripped
}

func isJSONWhitespace(char byte) bool {
	return char == ' ' || char == '\t' || char == '\r' || char == '\n'
}

// splitBunPackageDescriptor splits a bun.lock descriptor into a package name
// and a version.
//
//	"lodash@4.17.19"          -> "lodash", "4.17.19"
//	"@ctrl/tinycolor@4.1.1"   -> "@ctrl/tinycolor", "4.1.1"
//	"@probe/app@workspace:.." -> "@probe/app", "workspace:.."
//
// An npm package name only ever contains "@" as the scope prefix, so the
// separator is the first "@" after position zero. Using the last "@" instead
// would mis-split a tarball dependency whose URL carries userinfo.
func splitBunPackageDescriptor(descriptor string) (string, string) {
	descriptor = strings.TrimSpace(descriptor)
	if descriptor == "" {
		return "", ""
	}

	start := 0
	if strings.HasPrefix(descriptor, "@") {
		start = 1
	}

	separator := strings.Index(descriptor[start:], "@")
	if separator == -1 {
		return descriptor, ""
	}
	separator += start

	return descriptor[:separator], descriptor[separator+1:]
}

// bunPackageEntry is a package name/version pair resolved from a bun lockfile
type bunPackageEntry struct {
	name    string
	version string
}

func readBunLockEntries(path string) ([]bunPackageEntry, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var bunLock BunLock
	if err := json.Unmarshal(stripJSONC(data), &bunLock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Both checks below guard against the same failure: a future bun.lock that
	// still decodes cleanly into this struct but keeps its dependencies somewhere
	// this parser does not look. That would produce zero entries and no error,
	// which is exactly the false clean the scanner exists to prevent. Bun deletes
	// the lockfile outright when a project has no packages, so an existing
	// bun.lock always carries a "packages" object.
	if bunLock.LockfileVersion > maxKnownBunLockfileVersion {
		return nil, fmt.Errorf("failed to scan %s: lockfileVersion %d is newer than the supported version %d, so its dependencies were not read", path, bunLock.LockfileVersion, maxKnownBunLockfileVersion)
	}
	if bunLock.Packages == nil {
		return nil, fmt.Errorf("failed to scan %s: no \"packages\" object, so its dependencies were not read", path)
	}

	var entries []bunPackageEntry
	seen := make(map[bunPackageEntry]bool)

	// The map key is an install path rather than a package name — a second copy
	// of a dependency is keyed "chalk/supports-color" — so the name and version
	// are always taken from the descriptor instead.
	for _, entry := range bunLock.Packages {
		if len(entry) == 0 {
			continue
		}

		var descriptor string
		if err := json.Unmarshal(entry[0], &descriptor); err != nil {
			// Not a "name@version" string; nothing to match against.
			continue
		}

		name, version := splitBunPackageDescriptor(descriptor)
		if name == "" || version == "" {
			continue
		}

		packageEntry := bunPackageEntry{name: name, version: version}
		if seen[packageEntry] {
			continue
		}
		seen[packageEntry] = true
		entries = append(entries, packageEntry)
	}

	return entries, nil
}

func scanBunLockOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	entries, err := readBunLockEntries(path)
	if err != nil {
		return nil, err
	}

	var foundVulnerabilities []string
	for _, entry := range entries {
		if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(entry.name, entry.version); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(entry.name, entry.version, filepath.Base(path), vulnerablePackage))
		}
	}

	return foundVulnerabilities, nil
}

func scanPackageLockJSONOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageLockJSON PackageLockJSON
	if err := json.Unmarshal(data, &packageLockJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Determine lockfile version and scan accordingly
	if packageLockJSON.LockfileVersion >= 2 && len(packageLockJSON.Packages) > 0 {
		// v2/v3: use packages field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockPackagesOptimized(packageLockJSON.Packages, vulnerablePackageMap, filepath.Base(path))...)
	} else if len(packageLockJSON.Dependencies) > 0 {
		// v1: use dependencies field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependenciesOptimized(packageLockJSON.Dependencies, vulnerablePackageMap, filepath.Base(path))...)
	}

	return foundVulnerabilities, nil
}

func scanPackageLockJSON(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageLockJSON PackageLockJSON
	if err := json.Unmarshal(data, &packageLockJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Determine lockfile version and scan accordingly
	if packageLockJSON.LockfileVersion >= 2 && len(packageLockJSON.Packages) > 0 {
		// v2/v3: use packages field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockPackages(packageLockJSON.Packages, vulnerablePackages, filepath.Base(path))...)
	} else if len(packageLockJSON.Dependencies) > 0 {
		// v1: use dependencies field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependencies(packageLockJSON.Dependencies, vulnerablePackages, filepath.Base(path))...)
	}

	return foundVulnerabilities, nil
}

// scanPackageLockPackagesOptimized scans packages field (v2/v3) with optimized lookup
func scanPackageLockPackagesOptimized(packages map[string]PackageLockPackageInfo, vulnerablePackageMap VulnerablePackageMap, filename string) []string {
	var foundVulnerabilities []string
	for pkgPath, pkgInfo := range packages {
		// pkgPath is like "node_modules/@ctrl/tinycolor" or "" for root
		pkgName := strings.TrimPrefix(pkgPath, "node_modules/")
		if pkgName == "" || strings.Contains(pkgName, "/node_modules/") {
			continue // Skip root or nested node_modules
		}

		// Get the most accurate version available
		actualVersion := getActualVersion(pkgInfo.Version, pkgInfo.Resolved)

		if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, actualVersion); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(pkgName, actualVersion, filename, vulnerablePackage))
		}
	}
	return foundVulnerabilities
}

// scanPackageLockPackages scans packages field (v2/v3)
func scanPackageLockPackages(packages map[string]PackageLockPackageInfo, vulnerablePackages []VulnerablePackage, filename string) []string {
	var foundVulnerabilities []string
	for pkgPath, pkgInfo := range packages {
		// pkgPath is like "node_modules/@ctrl/tinycolor" or "" for root
		pkgName := strings.TrimPrefix(pkgPath, "node_modules/")
		if pkgName == "" || strings.Contains(pkgName, "/node_modules/") {
			continue // Skip root or nested node_modules
		}

		// Get the most accurate version available
		actualVersion := getActualVersion(pkgInfo.Version, pkgInfo.Resolved)

		for _, vulnerablePackage := range vulnerablePackages {
			if pkgName == vulnerablePackage.Name {
				if isVersionVulnerable(actualVersion, vulnerablePackage.Versions) {
					foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, actualVersion, filename, vulnerablePackage))
				}
			}
		}
	}
	return foundVulnerabilities
}

// scanPackageLockDependenciesOptimized scans dependencies field recursively (v1) with optimized lookup
func scanPackageLockDependenciesOptimized(dependencies map[string]PackageLockInfo, vulnerablePackageMap VulnerablePackageMap, filename string) []string {
	var foundVulnerabilities []string
	for pkgName, pkgInfo := range dependencies {
		if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, pkgInfo.Version); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(pkgName, pkgInfo.Version, filename, vulnerablePackage))
		}
		// Recursively scan nested dependencies
		if len(pkgInfo.Dependencies) > 0 {
			foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependenciesOptimized(pkgInfo.Dependencies, vulnerablePackageMap, filename)...)
		}
	}
	return foundVulnerabilities
}

// scanPackageLockDependencies scans dependencies field recursively (v1)
func scanPackageLockDependencies(dependencies map[string]PackageLockInfo, vulnerablePackages []VulnerablePackage, filename string) []string {
	var foundVulnerabilities []string
	for pkgName, pkgInfo := range dependencies {
		for _, vulnerablePackage := range vulnerablePackages {
			if pkgName == vulnerablePackage.Name {
				if isVersionVulnerable(pkgInfo.Version, vulnerablePackage.Versions) {
					foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, pkgInfo.Version, filename, vulnerablePackage))
				}
			}
		}
		// Recursively scan nested dependencies
		if len(pkgInfo.Dependencies) > 0 {
			foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependencies(pkgInfo.Dependencies, vulnerablePackages, filename)...)
		}
	}
	return foundVulnerabilities
}
