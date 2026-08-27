package static

import (
	"fmt"
	"log"

	"github.com/shogo82148/androidbinary/apk"
)

// Analyzer holds statically extracted data from the target APK.
type Analyzer struct {
	PackageName string
	VersionName string
	VersionCode int32
	Permissions map[string]bool
	Activities  []string
	Receivers   []string
	Services    []string
}

// NewAnalyzer parses the provided APK file path and extracts the AndroidManifest.xml details.
func NewAnalyzer(apkPath string) (*Analyzer, error) {
	pkg, err := apk.OpenFile(apkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open apk: %w", err)
	}
	defer pkg.Close()

	manifest := pkg.Manifest()
	
	analyzer := &Analyzer{
		PackageName: manifest.Package.MustString(),
		VersionName: manifest.VersionName.MustString(),
		VersionCode: manifest.VersionCode.MustInt32(),
		Permissions: make(map[string]bool),
	}

	// Extract requested permissions
	for _, perm := range manifest.UsesPermissions {
		analyzer.Permissions[perm.Name.MustString()] = true
	}

	// Safely extract component names
	for _, act := range manifest.App.Activities {
		analyzer.Activities = append(analyzer.Activities, act.Name.MustString())
	}

	log.Printf("static analyzer: parsed %s (v%s)", analyzer.PackageName, analyzer.VersionName)
	log.Printf("static analyzer: found %d permissions, %d activities", len(analyzer.Permissions), len(analyzer.Activities))

	return analyzer, nil
}

// HasPermission returns true if the app requested the given permission in its manifest.
func (a *Analyzer) HasPermission(permissionName string) bool {
	return a.Permissions[permissionName]
}
