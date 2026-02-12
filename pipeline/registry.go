package pipeline

// RegisterAllSteps registers all built-in step types with the engine.
// This is called during initialization to make all steps available.
// Steps from integrations, vulnscan, authscan, monitor, and reporting
// are all registered here.
func RegisterAllSteps(engine *Engine) {
	// Built-in steps are registered by their respective packages
	// via init() or explicit registration calls.
	//
	// Integration steps:
	//   engine.RegisterStep(&integrations.SubfinderStep{})
	//   engine.RegisterStep(&integrations.AmassStep{})
	//   engine.RegisterStep(&integrations.NmapStep{})
	//   engine.RegisterStep(&integrations.NucleiStep{})
	//   engine.RegisterStep(&integrations.SQLMapStep{})
	//   engine.RegisterStep(&integrations.DalfoxStep{})
	//   engine.RegisterStep(&integrations.LFIMapStep{})
	//
	// Vuln scanning steps:
	//   engine.RegisterStep(&vulnscan.TechDetectStep{})
	//   engine.RegisterStep(&vulnscan.CVEMapStep{})
	//   engine.RegisterStep(&vulnscan.SourceMapReconStep{})
	//
	// Auth scanning steps:
	//   engine.RegisterStep(&authscan.IDORStep{})
	//   engine.RegisterStep(&authscan.PrivEscStep{})
	//   engine.RegisterStep(&authscan.AuthBypassStep{})
	//
	// NOTE: Actual registration is done in main.go to avoid circular imports.
	// This function serves as a documentation placeholder and can be extended
	// with steps that don't cause import cycles.
}
