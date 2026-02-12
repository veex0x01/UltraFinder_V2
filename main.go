package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/veex0x01/ultrafinder/authscan"
	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/integrations"
	"github.com/veex0x01/ultrafinder/monitor"
	"github.com/veex0x01/ultrafinder/monitor/notify"
	"github.com/veex0x01/ultrafinder/pipeline"
	"github.com/veex0x01/ultrafinder/reporting"
	"github.com/veex0x01/ultrafinder/webui"
)

const (
	Version = "2.0.0"
	Author  = "veex0x01"
)

var banner = `
   __  ______             _______           __
  / / / / / /__________ _/ ____(_)___  ____/ /__  _____
 / / / / / __/ ___/ __ '/ /_  / / __ \/ __  / _ \/ ___/
/ /_/ / / /_/ /  / /_/ / __/ / / / / / /_/ /  __/ /
\____/_/\__/_/   \__,_/_/   /_/_/ /_/\__,_/\___/_/

UltraFinder v2.0.0 — Advanced Offensive Security Suite
Developed by veex0x01
`

var rootCmd = &cobra.Command{
	Use:   "ultrafinder",
	Short: "UltraFinder v2.0 — Advanced Offensive Security Suite",
	Long:  banner,
	Run:   crawlRun,
}

// =============================================================================
// scan subcommand — run v1-style crawling
// =============================================================================
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run web crawling and reconnaissance on a target",
	Run:   crawlRun,
}

// =============================================================================
// pipeline subcommand — run YAML pipeline
// =============================================================================
var pipelineCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "Run a YAML-defined pipeline",
	Run: func(cmd *cobra.Command, args []string) {
		pipelineFile, _ := cmd.Flags().GetString("file")
		target, _ := cmd.Flags().GetString("target")
		logFile, _ := cmd.Flags().GetString("log")
		htmlReport, _ := cmd.Flags().GetString("html")
		jsonReport, _ := cmd.Flags().GetString("json-export")
		csvReport, _ := cmd.Flags().GetString("csv-export")
		scope, _ := cmd.Flags().GetString("scope") // "all" or "exact"

		if pipelineFile == "" || target == "" {
			color.Red("[-] --file and --target are required")
			os.Exit(1)
		}

		// Logger
		logger, _ := reporting.NewLogger(logFile, reporting.INFO, false)
		defer logger.Close()

		// Pipeline engine
		engine := pipeline.NewEngine(logger)
		registerAllSteps(engine, logger)

		// Load and run pipeline
		p, err := engine.LoadPipeline(pipelineFile)
		if err != nil {
			color.Red("[-] Failed to load pipeline: %v", err)
			os.Exit(1)
		}

		// Inject scope variable
		if p.Variables == nil {
			p.Variables = make(map[string]string)
		}
		p.Variables["scope"] = scope

		logger.Info("Pipeline: %s — Target: %s", p.Name, target)
		ctx, err := engine.Run(p, target)
		if err != nil {
			color.Red("[-] Pipeline failed: %v", err)
			os.Exit(1)
		}

		// Export reports
		if htmlReport != "" {
			report := &reporting.HTMLReport{
				Title:     p.Name,
				Target:    target,
				StartTime: ctx.StartTime,
				EndTime:   time.Now(),
				Results:   ctx.AllResults,
			}
			if err := report.Generate(htmlReport); err != nil {
				logger.Error("HTML report failed: %v", err)
			} else {
				logger.Success("HTML report: %s", htmlReport)
			}
		}
		if jsonReport != "" {
			stats := reporting.NewScanStats()
			if err := reporting.ExportJSON(jsonReport, target, ctx.AllResults, stats, time.Since(ctx.StartTime)); err != nil {
				logger.Error("JSON export failed: %v", err)
			} else {
				logger.Success("JSON export: %s", jsonReport)
			}
		}
		if csvReport != "" {
			if err := reporting.ExportCSV(csvReport, ctx.AllResults); err != nil {
				logger.Error("CSV export failed: %v", err)
			} else {
				logger.Success("CSV export: %s", csvReport)
			}
		}
	},
}

// =============================================================================
// auth subcommand — auth/priv-esc testing
// =============================================================================
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication and privilege escalation testing",
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		highAuth, _ := cmd.Flags().GetString("high-session")
		lowAuth, _ := cmd.Flags().GetString("low-session")
		testIDOR, _ := cmd.Flags().GetBool("idor")
		testPrivesc, _ := cmd.Flags().GetBool("privesc")
		testBypass, _ := cmd.Flags().GetBool("bypass")

		if target == "" {
			color.Red("[-] --target is required")
			os.Exit(1)
		}

		logger, _ := reporting.NewLogger("", reporting.INFO, false)
		output, _ := core.NewOutput("", false, false)

		sessions := authscan.NewSessionManager()
		if highAuth != "" {
			sessions.AddSession(authscan.ParseSessionFromFlags("high", highAuth))
		}
		if lowAuth != "" {
			sessions.AddSession(authscan.ParseSessionFromFlags("low", lowAuth))
		}

		var allResults []core.Result

		if testIDOR {
			logger.Info("Running IDOR scan on %s", target)
			scanner := authscan.NewIDORScanner(sessions, output, logger)
			results := scanner.ScanEndpoint(target, "GET")
			allResults = append(allResults, results...)
		}

		if testPrivesc {
			logger.Info("Running privilege escalation scan on %s", target)
			scanner := authscan.NewPrivEscScanner(sessions, output, logger)
			results := scanner.ScanAllPaths(target, "high", "low")
			allResults = append(allResults, results...)
		}

		if testBypass {
			logger.Info("Running auth bypass scan on %s", target)
			scanner := authscan.NewAuthBypassScanner(sessions, output, logger)
			results := scanner.ScanURLs([]string{target})
			allResults = append(allResults, results...)
		}

		logger.Success("Auth scan complete: %d findings", len(allResults))
	},
}

// =============================================================================
// proxy subcommand — MITM intercepting proxy
// =============================================================================
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start MITM intercepting proxy for auth testing",
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		scope, _ := cmd.Flags().GetString("scope")
		autoTest, _ := cmd.Flags().GetBool("auto-test")

		logger, _ := reporting.NewLogger("", reporting.INFO, false)
		sessions := authscan.NewSessionManager()

		proxy := authscan.NewInterceptProxy(listen, scope, sessions, logger)
		proxy.AutoTest = autoTest

		ip := authscan.GetLocalIP()
		logger.Info("Configure your browser proxy: %s:%s", ip, listen)

		if err := proxy.Start(); err != nil {
			color.Red("[-] Proxy failed: %v", err)
			os.Exit(1)
		}
	},
}

// =============================================================================
// monitor subcommand — change monitoring with notifications
// =============================================================================
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor targets for changes with notifications",
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		interval, _ := cmd.Flags().GetString("interval")
		screenshot, _ := cmd.Flags().GetBool("screenshot")
		contentDiff, _ := cmd.Flags().GetBool("diff")
		telegramToken, _ := cmd.Flags().GetString("telegram-token")
		telegramChat, _ := cmd.Flags().GetString("telegram-chat")
		slackWebhook, _ := cmd.Flags().GetString("slack-webhook")
		discordWebhook, _ := cmd.Flags().GetString("discord-webhook")
		webhookURL, _ := cmd.Flags().GetString("webhook")
		once, _ := cmd.Flags().GetBool("once")

		if target == "" {
			color.Red("[-] --target is required")
			os.Exit(1)
		}

		logger, _ := reporting.NewLogger("", reporting.INFO, false)
		dispatcher := notify.NewDispatcher(logger)

		// Register notification channels
		if telegramToken != "" && telegramChat != "" {
			dispatcher.AddChannel(notify.NewTelegramNotifier(telegramToken, telegramChat))
		}
		if slackWebhook != "" {
			dispatcher.AddChannel(notify.NewSlackNotifier(slackWebhook, ""))
		}
		if discordWebhook != "" {
			dispatcher.AddChannel(notify.NewDiscordNotifier(discordWebhook))
		}
		if webhookURL != "" {
			dispatcher.AddChannel(notify.NewWebhookNotifier(webhookURL))
		}

		// Parse interval
		dur, err := time.ParseDuration(interval)
		if err != nil {
			dur = 1 * time.Hour
		}

		scheduler := monitor.NewScheduler(logger, dispatcher)

		// Setup engines
		if screenshot {
			scheduler.Screenshot = monitor.NewScreenshotEngine("./screenshots", logger)
		}
		if contentDiff {
			scheduler.Diff = monitor.NewDiffMonitor("./.monitor-data", logger)
		}

		scheduler.AddTarget(monitor.WatchTarget{
			URL:         target,
			Interval:    dur,
			Screenshot:  screenshot,
			ContentDiff: contentDiff,
		})

		if once {
			results := scheduler.RunOnce()
			logger.Success("One-time check complete: %d changes", len(results))
		} else {
			logger.Info("Starting continuous monitoring (interval: %s)", dur)
			scheduler.Start()
			// Block forever
			select {}
		}
	},
}

// =============================================================================
// webui subcommand — launch web dashboard
// =============================================================================
var webuiCmd = &cobra.Command{
	Use:   "webui",
	Short: "Launch the web dashboard",
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		user, _ := cmd.Flags().GetString("auth-user")
		pass, _ := cmd.Flags().GetString("auth-pass")

		logger, _ := reporting.NewLogger("", reporting.INFO, false)

		engine := pipeline.NewEngine(logger)
		registerAllSteps(engine, logger)

		server := webui.NewServer(listen, engine, logger, user, pass)

		fmt.Println(banner)
		logger.Info("Starting Web UI on http://%s", listen)

		if err := server.Start(); err != nil {
			color.Red("[-] Web UI failed: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	// ===== ROOT/SCAN FLAGS (backward compatible v1) =====
	for _, cmd := range []*cobra.Command{rootCmd, scanCmd} {
		cmd.Flags().StringP("url", "u", "", "Target URL (required)")
		cmd.Flags().IntP("depth", "d", 2, "Maximum crawl depth")
		cmd.Flags().IntP("threads", "t", 10, "Number of concurrent threads")
		cmd.Flags().IntP("timeout", "m", 30, "Request timeout in seconds")
		cmd.Flags().IntP("delay", "k", 0, "Delay between requests in seconds")
		cmd.Flags().Int("random-delay", 0, "Random delay jitter in ms")
		cmd.Flags().StringP("proxy", "p", "", "Proxy URL")
		cmd.Flags().StringP("cookie", "c", "", "Cookie string")
		cmd.Flags().StringArrayP("header", "H", []string{}, "Custom header")
		cmd.Flags().StringP("user-agent", "a", "", "Custom User-Agent")
		cmd.Flags().Bool("no-redirect", false, "Disable following redirects")
		cmd.Flags().Bool("stealth", false, "Enable stealth mode")
		cmd.Flags().Bool("random-ua", false, "Use random User-Agent")
		cmd.Flags().Bool("deep", false, "Enable deep analysis")
		cmd.Flags().Bool("subs", false, "Include subdomains")
		cmd.Flags().Bool("wayback", false, "Fetch from Wayback Machine")
		cmd.Flags().Bool("commoncrawl", false, "Fetch from CommonCrawl")
		cmd.Flags().Bool("otx", false, "Fetch from AlienVault OTX")
		cmd.Flags().Bool("all-sources", false, "Fetch from all sources")
		cmd.Flags().StringP("output", "o", "", "Output file path")
		cmd.Flags().Bool("json", false, "Output as JSON")
		cmd.Flags().BoolP("quiet", "q", false, "Suppress console output")
		cmd.Flags().BoolP("verbose", "v", false, "Verbose output")
		cmd.Flags().Bool("version", false, "Print version")
	}

	// ===== PIPELINE FLAGS =====
	pipelineCmd.Flags().StringP("file", "f", "", "Pipeline YAML file (required)")
	pipelineCmd.Flags().StringP("target", "t", "", "Target URL/domain (required)")
	pipelineCmd.Flags().String("log", "", "Log output file")
	pipelineCmd.Flags().String("html", "", "Export HTML report")
	pipelineCmd.Flags().StringP("json-export", "j", "", "Export results to JSON file")
	pipelineCmd.Flags().StringP("csv-export", "c", "", "Export results to CSV file")
	pipelineCmd.Flags().String("scope", "all", "Scope: 'all' (subs+domain) or 'exact' (domain only)")

	// ===== AUTH FLAGS =====
	authCmd.Flags().StringP("target", "t", "", "Target URL (required)")
	authCmd.Flags().String("high-session", "", "High-priv session (e.g., 'Cookie: session=admin')")
	authCmd.Flags().String("low-session", "", "Low-priv session (e.g., 'Cookie: session=user')")
	authCmd.Flags().Bool("idor", false, "Test for IDOR vulnerabilities")
	authCmd.Flags().Bool("privesc", false, "Test for privilege escalation")
	authCmd.Flags().Bool("bypass", false, "Test for auth bypass")

	// ===== PROXY FLAGS =====
	proxyCmd.Flags().StringP("listen", "l", ":8888", "Proxy listen address")
	proxyCmd.Flags().StringP("scope", "s", "", "Target scope domain")
	proxyCmd.Flags().Bool("auto-test", false, "Auto-test captured requests")

	// ===== MONITOR FLAGS =====
	monitorCmd.Flags().StringP("target", "t", "", "Target URL to monitor (required)")
	monitorCmd.Flags().String("interval", "1h", "Check interval (e.g. 30m, 1h, 24h)")
	monitorCmd.Flags().Bool("screenshot", false, "Enable screenshot comparison")
	monitorCmd.Flags().Bool("diff", false, "Enable content diff monitoring")
	monitorCmd.Flags().Bool("once", false, "Run once and exit")
	monitorCmd.Flags().String("telegram-token", "", "Telegram bot token")
	monitorCmd.Flags().String("telegram-chat", "", "Telegram chat ID")
	monitorCmd.Flags().String("slack-webhook", "", "Slack webhook URL")
	monitorCmd.Flags().String("discord-webhook", "", "Discord webhook URL")
	monitorCmd.Flags().String("webhook", "", "Generic webhook URL")

	// ===== WEBUI FLAGS =====
	webuiCmd.Flags().StringP("listen", "l", ":8080", "Web UI listen address")
	webuiCmd.Flags().String("auth-user", "", "Basic auth username")
	webuiCmd.Flags().String("auth-pass", "", "Basic auth password")

	// Register subcommands
	rootCmd.AddCommand(scanCmd, pipelineCmd, authCmd, proxyCmd, monitorCmd, webuiCmd)
}

// crawlRun handles the legacy/scan subcommand
func crawlRun(cmd *cobra.Command, args []string) {
	version, _ := cmd.Flags().GetBool("version")
	if version {
		fmt.Printf("UltraFinder v%s by %s\n", Version, Author)
		os.Exit(0)
	}

	targetURL, _ := cmd.Flags().GetString("url")
	if targetURL == "" {
		fmt.Println(banner)
		cmd.Help()
		return
	}

	depth, _ := cmd.Flags().GetInt("depth")
	threads, _ := cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetInt("timeout")
	delay, _ := cmd.Flags().GetInt("delay")
	randomDelay, _ := cmd.Flags().GetInt("random-delay")
	proxy, _ := cmd.Flags().GetString("proxy")
	cookie, _ := cmd.Flags().GetString("cookie")
	headers, _ := cmd.Flags().GetStringArray("header")
	userAgent, _ := cmd.Flags().GetString("user-agent")
	noRedirect, _ := cmd.Flags().GetBool("no-redirect")
	stealthMode, _ := cmd.Flags().GetBool("stealth")
	randomUA, _ := cmd.Flags().GetBool("random-ua")
	deepAnalysis, _ := cmd.Flags().GetBool("deep")
	includeSubs, _ := cmd.Flags().GetBool("subs")
	useWayback, _ := cmd.Flags().GetBool("wayback")
	useCommonCrawl, _ := cmd.Flags().GetBool("commoncrawl")
	useOTX, _ := cmd.Flags().GetBool("otx")
	allSources, _ := cmd.Flags().GetBool("all-sources")
	outputFile, _ := cmd.Flags().GetString("output")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	quiet, _ := cmd.Flags().GetBool("quiet")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if allSources {
		useWayback = true
		useCommonCrawl = true
		useOTX = true
	}
	if stealthMode && randomDelay == 0 {
		randomDelay = 2000
	}

	config := core.Config{
		URL:             targetURL,
		MaxDepth:        depth,
		Concurrent:      threads,
		Timeout:         timeout,
		Delay:           delay,
		RandomDelay:     randomDelay,
		UserAgent:       userAgent,
		Proxy:           proxy,
		Cookie:          cookie,
		Headers:         headers,
		OutputFile:      outputFile,
		JSONOutput:      jsonOutput,
		Quiet:           quiet,
		Verbose:         verbose,
		IncludeSubs:     includeSubs,
		UseWayback:      useWayback,
		UseCommonCrawl:  useCommonCrawl,
		UseOTX:          useOTX,
		DisableRedirect: noRedirect,
		StealthMode:     stealthMode,
		RandomUA:        randomUA,
		DeepAnalysis:    deepAnalysis,
	}

	crawler, err := core.NewCrawler(config)
	if err != nil {
		color.Red("[-] Error creating crawler: %v", err)
		os.Exit(1)
	}

	crawler.Run(context.Background())
}

// registerAllSteps registers all integration steps with the pipeline engine
func registerAllSteps(engine *pipeline.Engine, logger *reporting.Logger) {
	runner := integrations.NewToolRunner(logger)
	engine.RegisterStep(&integrations.SubfinderStep{Runner: runner})
	engine.RegisterStep(&integrations.AmassStep{Runner: runner})
	engine.RegisterStep(&integrations.NmapStep{Runner: runner})
	engine.RegisterStep(&integrations.HttpxStep{Runner: runner})
	engine.RegisterStep(&integrations.KatanaStep{Runner: runner})
	engine.RegisterStep(&integrations.ParamFilterStep{})
	engine.RegisterStep(&integrations.InternalCrawlerStep{Runner: runner})
	engine.RegisterStep(&integrations.SimpleProbeStep{Runner: runner})
	engine.RegisterStep(&integrations.TechFinderStep{Runner: runner})  // New: Advanced tech detection
	engine.RegisterStep(&integrations.NucleiStep{Runner: runner})
	engine.RegisterStep(&integrations.ShodanStep{Runner: runner})        // New: Shodan CVE enumeration
	engine.RegisterStep(&integrations.SmartNucleiStep{Runner: runner})   // New: Intelligent Nuclei
	engine.RegisterStep(&integrations.SQLMapStep{Runner: runner})
	engine.RegisterStep(&integrations.DalfoxStep{Runner: runner})
	engine.RegisterStep(&integrations.LFIMapStep{Runner: runner})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("[-] Error: %v", err)
		os.Exit(1)
	}
}
