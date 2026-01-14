package version

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// BuildInfo contains comprehensive build information
type BuildInfo struct {
	Version   string    `json:"version"`
	CommitSHA string    `json:"commit_sha"`
	BuildTime time.Time `json:"build_time"`
	GoVersion string    `json:"go_version"`
	Platform  string    `json:"platform"`
	BuildType string    `json:"build_type"`
	Branch    string    `json:"branch,omitempty"`
	Tag       string    `json:"tag,omitempty"`
	Dirty     bool      `json:"dirty,omitempty"`
}

// VersionInfo represents semantic version information
type VersionInfo struct {
	Major      int    `json:"major"`
	Minor      int    `json:"minor"`
	Patch      int    `json:"patch"`
	PreRelease string `json:"prerelease,omitempty"`
	Build      string `json:"build,omitempty"`
}

// String returns the string representation of the version
func (v VersionInfo) String() string {
	version := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.PreRelease != "" {
		version += "-" + v.PreRelease
	}
	if v.Build != "" {
		version += "+" + v.Build
	}
	return version
}

// IsRelease checks if this is a release version (no pre-release or build metadata)
func (v VersionInfo) IsRelease() bool {
	return v.PreRelease == "" && v.Build == ""
}

// Compare compares two versions following semantic versioning rules
func (v VersionInfo) Compare(other VersionInfo) int {
	if v.Major != other.Major {
		return v.Major - other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor - other.Minor
	}
	if v.Patch != other.Patch {
		return v.Patch - other.Patch
	}

	// Pre-release comparison (release > pre-release)
	if v.PreRelease == "" && other.PreRelease != "" {
		return 1
	}
	if v.PreRelease != "" && other.PreRelease == "" {
		return -1
	}

	// Simple string comparison for pre-release identifiers
	return strings.Compare(v.PreRelease, other.PreRelease)
}

// Default build information (will be overridden at build time)
var (
	buildVersion   = "dev"
	buildCommit    = "unknown"
	buildTime      = time.Now().UTC()
	buildGoVersion = runtime.Version()
	buildPlatform  = runtime.GOOS + "/" + runtime.GOARCH
	buildType      = "development"
	buildBranch    = ""
	buildTag       = ""
	buildDirty     = false
)

// SetBuildInfo allows setting build information (used by build scripts)
func SetBuildInfo(version, commit, branch, tag, buildTypeStr string, dirty bool) {
	if version != "" {
		buildVersion = version
	}
	if commit != "" {
		buildCommit = commit
	}
	if branch != "" {
		buildBranch = branch
	}
	if tag != "" {
		buildTag = tag
	}
	if buildTypeStr != "" {
		buildType = buildTypeStr
	}
	buildDirty = dirty

	// Parse build time if provided in ISO format
	if strings.Contains(version, "T") {
		if t, err := time.Parse(time.RFC3339, version); err == nil {
			buildTime = t
			return
		}
	}
}

// ParseBuildTime parses build time from string
func ParseBuildTime(timeStr string) {
	if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
		buildTime = t
	}
}

// GetBuildInfo returns current build information
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   buildVersion,
		CommitSHA: buildCommit,
		BuildTime: buildTime,
		GoVersion: buildGoVersion,
		Platform:  buildPlatform,
		BuildType: buildType,
		Branch:    buildBranch,
		Tag:       buildTag,
		Dirty:     buildDirty,
	}
}

// GetVersion parses and returns VersionInfo
func GetVersion() (VersionInfo, error) {
	return ParseVersion(buildVersion)
}

// ParseVersion parses a version string into VersionInfo
func ParseVersion(version string) (VersionInfo, error) {
	var vi VersionInfo

	// Handle special case
	if version == "dev" {
		return VersionInfo{Major: 0, Minor: 0, Patch: 0, PreRelease: "dev"}, nil
	}

	// Split version from build metadata
	parts := strings.SplitN(version, "+", 2)
	versionPart := parts[0]
	if len(parts) == 2 {
		vi.Build = parts[1]
	}

	// Split version from pre-release
	versionParts := strings.SplitN(versionPart, "-", 2)
	versionCore := versionParts[0]
	if len(versionParts) == 2 {
		vi.PreRelease = versionParts[1]
	}

	// Parse core version (x.y.z)
	_, err := fmt.Sscanf(versionCore, "%d.%d.%d", &vi.Major, &vi.Minor, &vi.Patch)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("invalid version format: %s", version)
	}

	return vi, nil
}

// IsDevelopment checks if this is a development build
func IsDevelopment() bool {
	return buildType == "development" || buildVersion == "dev"
}

// IsPreRelease checks if this is a pre-release version
func IsPreRelease() bool {
	ver, err := GetVersion()
	if err != nil {
		return true
	}
	return !ver.IsRelease()
}

// IsRelease checks if this is a release version
func IsRelease() bool {
	ver, err := GetVersion()
	if err != nil {
		return false
	}
	return ver.IsRelease()
}

// FormatInfo returns formatted build information
func FormatInfo() string {
	info := GetBuildInfo()

	result := fmt.Sprintf("net-watcher v%s\n", info.Version)
	result += fmt.Sprintf("Commit:    %s\n", info.CommitSHA)
	result += fmt.Sprintf("Build:     %s\n", info.BuildTime.Format(time.RFC3339))
	result += fmt.Sprintf("Go:        %s\n", info.GoVersion)
	result += fmt.Sprintf("Platform:  %s\n", info.Platform)
	result += fmt.Sprintf("Type:      %s\n", info.BuildType)

	if info.Branch != "" {
		result += fmt.Sprintf("Branch:    %s\n", info.Branch)
	}
	if info.Tag != "" {
		result += fmt.Sprintf("Tag:       %s\n", info.Tag)
	}
	if info.Dirty {
		result += "Dirty:     true\n"
	}

	return result
}

// FormatJSON returns build information as JSON
func FormatJSON() (string, error) {
	info := GetBuildInfo()
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatCompact returns compact version information
func FormatCompact() string {
	info := GetBuildInfo()
	if info.Dirty {
		return fmt.Sprintf("%s-dirty (%s)", info.Version, info.CommitSHA[:8])
	}
	return fmt.Sprintf("%s (%s)", info.Version, info.CommitSHA[:8])
}
