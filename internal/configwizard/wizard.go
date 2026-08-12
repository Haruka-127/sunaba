// Package configwizard provides the bounded, host-side Project configuration wizard.
package configwizard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"sunaba/internal/modelcatalog"
	"sunaba/internal/modelgateway"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/trustedui"
	"sunaba/internal/webgateway"
)

const maximumInputLine = 4096

var ErrCanceled = errors.New("Project configuration wizard canceled")

type Result struct {
	Config projectconfig.Config
	Rules  []webgateway.OriginRule
}

type Options struct {
	SuggestedGitRemotes []policy.GitRemotePolicy
}

type wizard struct {
	scanner *bufio.Scanner
	output  io.Writer
}

// Run edits a candidate entirely in memory and returns it only after final confirmation.
func Run(input io.Reader, output io.Writer, current projectconfig.Config, currentRules []webgateway.OriginRule) (Result, error) {
	return RunWithOptions(input, output, current, currentRules, Options{})
}

// RunWithOptions adds validated host-side suggestions without trusting or
// automatically enabling them.
func RunWithOptions(input io.Reader, output io.Writer, current projectconfig.Config, currentRules []webgateway.OriginRule, options Options) (Result, error) {
	if input == nil || output == nil {
		return Result{}, fmt.Errorf("configuration wizard input and output are required")
	}
	if err := projectconfig.Validate(current, currentRules); err != nil {
		return Result{}, err
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 256), maximumInputLine)
	w := &wizard{scanner: scanner, output: output}
	candidate := current
	candidate.Model.AllowedModels = append([]string(nil), current.Model.AllowedModels...)
	candidate.Git.Remotes = append([]policy.GitRemotePolicy(nil), current.Git.Remotes...)
	rules := append([]webgateway.OriginRule(nil), currentRules...)

	fmt.Fprintln(output, "sunaba Project設定ウィザード（qでキャンセル）")
	var err error
	if candidate.Mode, err = w.mode(candidate.Mode); err != nil {
		return Result{}, err
	}
	if candidate.Model, err = w.model(candidate.Model); err != nil {
		return Result{}, err
	}
	if candidate.Git.Remotes, err = w.git(candidate.Git.Remotes, options.SuggestedGitRemotes); err != nil {
		return Result{}, err
	}
	if candidate.Web, rules, err = w.web(candidate.Web, rules); err != nil {
		return Result{}, err
	}
	advanced, err := w.yesNo("resource、session、quota、exportの詳細設定を変更しますか？", false)
	if err != nil {
		return Result{}, err
	}
	if advanced {
		if err := w.advanced(&candidate); err != nil {
			return Result{}, err
		}
	}
	if err := projectconfig.Validate(candidate, rules); err != nil {
		return Result{}, fmt.Errorf("設定候補は無効です: %w", err)
	}
	w.summary(candidate, rules)
	confirmed, err := w.yesNo("この設定を保存して適用しますか？", false)
	if err != nil {
		return Result{}, err
	}
	if !confirmed {
		return Result{}, ErrCanceled
	}
	return Result{Config: candidate, Rules: rules}, nil
}

func (w *wizard) mode(current string) (string, error) {
	defaultChoice := 1
	if current == "dev" {
		defaultChoice = 2
	}
	fmt.Fprintln(w.output, "\n実行モード:")
	fmt.Fprintln(w.output, "  1. secure（推奨、直接egressなし）")
	fmt.Fprintln(w.output, "  2. dev（active session中は直接Internet egressあり）")
	choice, err := w.choice("選択", defaultChoice, 2)
	if err != nil {
		return "", err
	}
	if choice == 1 {
		return "secure", nil
	}
	fmt.Fprintln(w.output, "WARNING: dev modeは情報流出防止を保証しません。host、LAN、credential、worktreeの境界は維持されます。")
	confirmed, err := w.yesNo("dev modeを選択しますか？", false)
	if err != nil {
		return "", err
	}
	if !confirmed {
		return "secure", nil
	}
	return "dev", nil
}

func (w *wizard) model(current policy.ModelPolicy) (policy.ModelPolicy, error) {
	change, err := w.yesNo("\nModel Gateway設定を変更しますか？", false)
	if err != nil || !change {
		return current, err
	}
	fmt.Fprintln(w.output, "Model認証方式:")
	fmt.Fprintln(w.output, "  1. API key（従量課金）")
	fmt.Fprintln(w.output, "  2. OAuth（ChatGPT Codex subscription）")
	defaultChoice := 1
	if current.AuthMode == modelcatalog.AuthOAuth {
		defaultChoice = 2
	}
	choice, err := w.choice("選択", defaultChoice, 2)
	if err != nil {
		return current, err
	}
	mode := modelcatalog.AuthAPIKey
	if choice == 2 {
		mode = modelcatalog.AuthOAuth
	}
	available, err := modelcatalog.Available(mode)
	if err != nil {
		return current, err
	}
	selected := append([]string(nil), current.AllowedModels...)
	if _, err := modelcatalog.Resolve(mode, selected); err != nil {
		selected, err = modelcatalog.DefaultModels(mode)
		if err != nil {
			return current, err
		}
	}
	fmt.Fprintln(w.output, "許可model（入力順の先頭が既定model）:")
	indexes := make(map[string]int, len(available))
	for index, definition := range available {
		indexes[definition.ID] = index + 1
		fmt.Fprintf(w.output, "  %d. %s (input=%d, output=%d)\n", index+1, definition.ID, definition.Limit.Input, definition.Limit.Output)
	}
	defaults := make([]string, 0, len(selected))
	for _, id := range selected {
		defaults = append(defaults, strconv.Itoa(indexes[id]))
	}
	for {
		line, err := w.line(fmt.Sprintf("model番号をカンマ区切りで入力 [%s]: ", strings.Join(defaults, ",")))
		if err != nil {
			return current, err
		}
		if line == "" {
			line = strings.Join(defaults, ",")
		}
		ids, err := parseModelSelection(line, available)
		if err == nil {
			current.AuthMode = mode
			current.AllowedModels = ids
			return current, nil
		}
		fmt.Fprintf(w.output, "入力エラー: %v\n", err)
	}
}

func parseModelSelection(raw string, available []modelcatalog.Model) ([]string, error) {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > 32 {
		return nil, fmt.Errorf("1から32件のmodelを選択してください")
	}
	result := make([]string, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		index, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || index < 1 || index > len(available) {
			return nil, fmt.Errorf("model番号が範囲外です")
		}
		if _, exists := seen[index]; exists {
			return nil, fmt.Errorf("同じmodelが重複しています")
		}
		seen[index] = struct{}{}
		result = append(result, available[index-1].ID)
	}
	return result, nil
}

func (w *wizard) git(current, suggested []policy.GitRemotePolicy) ([]policy.GitRemotePolicy, error) {
	enabled, err := w.yesNo("\nGit Gatewayを使用しますか？", len(current) > 0)
	if err != nil || !enabled {
		return nil, err
	}
	kept := make([]policy.GitRemotePolicy, 0, len(current))
	for _, remote := range current {
		keep, err := w.yesNo(fmt.Sprintf("remote %s (%s) を保持しますか？", safe(remote.Name), safe(remote.URL)), true)
		if err != nil {
			return nil, err
		}
		if keep {
			kept = append(kept, remote)
		}
	}
	for _, remote := range suggested {
		if policy.ValidateGitRemote(remote) != nil || remoteExists(kept, remote) {
			continue
		}
		use, err := w.yesNo(fmt.Sprintf("Projectから検出したremote %s (%s) をGit Gatewayに登録しますか？", safe(remote.Name), safe(remote.URL)), true)
		if err != nil {
			return nil, err
		}
		if use {
			kept = append(kept, remote)
		}
	}
	for {
		add, err := w.yesNo("Git Gateway remoteを追加しますか？", len(kept) == 0)
		if err != nil {
			return nil, err
		}
		if !add {
			if len(kept) == 0 {
				fmt.Fprintln(w.output, "remoteがないためGit Gatewayは無効になります。")
			}
			return kept, nil
		}
		name, err := w.requiredLine("remote名（例: origin）: ")
		if err != nil {
			return nil, err
		}
		remoteURL, err := w.requiredLine("credentialを含まないHTTPS .git URL: ")
		if err != nil {
			return nil, err
		}
		candidate := policy.GitRemotePolicy{Name: name, URL: remoteURL}
		if err := policy.ValidateGitRemote(candidate); err != nil {
			fmt.Fprintf(w.output, "入力エラー: %v\n", err)
			continue
		}
		if remoteExists(kept, candidate) {
			fmt.Fprintln(w.output, "入力エラー: remote名またはURLが重複しています。")
			continue
		}
		kept = append(kept, candidate)
		if len(kept) == 16 {
			return kept, nil
		}
	}
}

func remoteExists(remotes []policy.GitRemotePolicy, candidate policy.GitRemotePolicy) bool {
	for _, existing := range remotes {
		if existing.Name == candidate.Name || existing.URL == candidate.URL {
			return true
		}
	}
	return false
}

func (w *wizard) web(currentConfig projectconfig.WebConfig, current []webgateway.OriginRule) (projectconfig.WebConfig, []webgateway.OriginRule, error) {
	enabled, err := w.yesNo("\nWeb Gatewayを使用しますか？", currentConfig.Enabled)
	if err != nil {
		return currentConfig, nil, err
	}
	if !enabled {
		currentConfig.Enabled = false
		return currentConfig, append([]webgateway.OriginRule(nil), current...), nil
	}
	fmt.Fprintln(w.output, "NOTICE: HTTPSはTLS非終端tunnelのため、内部のmethod、path、upload内容は識別・保証できません。")
	fmt.Fprintln(w.output, "NOTICE: common-development presetはpackage registry、CDN、public object storageを含む広い許可集合です。")
	useCommonPreset, err := w.yesNo("組み込みcommon-development origin presetを使用しますか？", containsString(currentConfig.OriginPresets, webgateway.CommonDevelopmentOriginPreset))
	if err != nil {
		return currentConfig, nil, err
	}
	currentConfig.OriginPresets = nil
	if useCommonPreset {
		currentConfig.OriginPresets = []string{webgateway.CommonDevelopmentOriginPreset}
	}
	kept := make([]webgateway.OriginRule, 0, len(current))
	for _, rule := range current {
		keep, err := w.yesNo(fmt.Sprintf("origin %s を保持しますか？", formatOrigin(rule)), true)
		if err != nil {
			return currentConfig, nil, err
		}
		if keep {
			kept = append(kept, rule)
		}
	}
	for {
		add, err := w.yesNo("Project固有Web originを追加しますか？", len(kept) == 0 && len(currentConfig.OriginPresets) == 0)
		if err != nil {
			return currentConfig, nil, err
		}
		if !add && (len(kept) > 0 || len(currentConfig.OriginPresets) > 0) {
			currentConfig.Enabled = true
			return currentConfig, kept, nil
		}
		if !add {
			fmt.Fprintln(w.output, "Web Gatewayには少なくとも1件のoriginが必要です。")
			continue
		}
		raw, err := w.requiredLine("HTTP(S) origin（pathなし）: ")
		if err != nil {
			return currentConfig, nil, err
		}
		include, err := w.yesNo("subdomainも許可しますか？", false)
		if err != nil {
			return currentConfig, nil, err
		}
		rule, err := projectconfig.ParseOrigin(raw, include)
		if err != nil {
			fmt.Fprintf(w.output, "入力エラー: %v\n", err)
			continue
		}
		duplicate := false
		for _, existing := range kept {
			if formatOrigin(existing) == formatOrigin(rule) {
				duplicate = true
				break
			}
		}
		if duplicate {
			fmt.Fprintln(w.output, "入力エラー: originが重複しています。")
			continue
		}
		kept = append(kept, rule)
		if len(kept) == 1024 {
			currentConfig.Enabled = true
			return currentConfig, kept, nil
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (w *wizard) advanced(config *projectconfig.Config) error {
	fmt.Fprintln(w.output, "\n詳細設定（Enterで現在値を維持）")
	var err error
	if config.Resources.CPUs, err = w.integer("CPU数", config.Resources.CPUs, 1, 32); err != nil {
		return err
	}
	if config.Resources.Memory, err = w.memory(config.Resources.Memory); err != nil {
		return err
	}
	diskMiB, err := w.int64("workspace disk (MiB)", config.Resources.DiskBytes>>20, 64, 8192)
	if err != nil {
		return err
	}
	config.Resources.DiskBytes = diskMiB << 20
	config.Resources.FileSizeMax = config.Resources.DiskBytes
	if config.Resources.ProcessMax, err = w.int64("process上限", config.Resources.ProcessMax, 16, 4096); err != nil {
		return err
	}
	if config.Resources.OpenFileMax, err = w.int64("open file上限", config.Resources.OpenFileMax, 256, 1<<20); err != nil {
		return err
	}
	if config.Session.TTLSeconds, err = w.duration("session TTL", config.Session.TTLSeconds, 1, 86400); err != nil {
		return err
	}
	if config.Session.IdleSeconds, err = w.duration("idle timeout", config.Session.IdleSeconds, 1, config.Session.TTLSeconds); err != nil {
		return err
	}
	if config.Model.MaxRequests, err = w.integer("Model request上限", config.Model.MaxRequests, 1, modelgateway.MaximumMaxRequests); err != nil {
		return err
	}
	if config.Model.MaxConcurrent, err = w.integer("Model同時request上限", config.Model.MaxConcurrent, 1, modelgateway.MaximumMaxConcurrent); err != nil {
		return err
	}
	requestMiB, err := w.int64("Model request body上限 (MiB)", config.Model.MaxRequestBytes>>20, 1, modelgateway.MaximumMaxRequestBytes>>20)
	if err != nil {
		return err
	}
	responseMiB, err := w.int64("Model response body上限 (MiB)", config.Model.MaxResponseBytes>>20, 1, modelgateway.MaximumMaxResponseBytes>>20)
	if err != nil {
		return err
	}
	config.Model.MaxRequestBytes, config.Model.MaxResponseBytes = requestMiB<<20, responseMiB<<20
	if config.Web.Enabled {
		if config.Web.MaxRequests, err = w.integer("Web request上限", config.Web.MaxRequests, 1, int(^uint(0)>>1)); err != nil {
			return err
		}
		if config.Web.MaxConcurrent, err = w.integer("Web同時接続上限", config.Web.MaxConcurrent, 1, int(^uint(0)>>1)); err != nil {
			return err
		}
		if config.Web.MaxConnectSeconds, err = w.int64("Web接続時間上限 (秒)", config.Web.MaxConnectSeconds, 1, 600); err != nil {
			return err
		}
		maximumMiB := int64((1 << 62) >> 20)
		uploadMiB, err := w.int64("Web upload上限 (MiB)", config.Web.MaxUploadBytes>>20, 1, maximumMiB)
		if err != nil {
			return err
		}
		downloadMiB, err := w.int64("Web download上限 (MiB)", config.Web.MaxDownloadBytes>>20, 1, maximumMiB)
		if err != nil {
			return err
		}
		totalMiB, err := w.int64("Web session合計上限 (MiB)", config.Web.MaxTotalBytes>>20, 1, maximumMiB)
		if err != nil {
			return err
		}
		config.Web.MaxUploadBytes, config.Web.MaxDownloadBytes, config.Web.MaxTotalBytes = uploadMiB<<20, downloadMiB<<20, totalMiB<<20
	}
	if config.Export.MaxEntries, err = w.integer("export entry上限", config.Export.MaxEntries, 1, 1_000_000); err != nil {
		return err
	}
	fileMiB, err := w.int64("export単一file上限 (MiB)", config.Export.MaxFileBytes>>20, 1, 8192)
	if err != nil {
		return err
	}
	totalMiB, err := w.int64("export合計上限 (MiB)", config.Export.MaxTotalBytes>>20, fileMiB, 8192)
	if err != nil {
		return err
	}
	config.Export.MaxFileBytes, config.Export.MaxTotalBytes = fileMiB<<20, totalMiB<<20
	config.Audit.RetentionDays, err = w.integer("audit保持日数", config.Audit.RetentionDays, 1, 365)
	return err
}

func (w *wizard) summary(config projectconfig.Config, rules []webgateway.OriginRule) {
	fmt.Fprintln(w.output, "\n適用する設定:")
	fmt.Fprintf(w.output, "  mode: %s\n", safe(config.Mode))
	fmt.Fprintf(w.output, "  model: auth=%s, default=%s, allowed=%s\n", safe(string(config.Model.AuthMode)), safe(config.Model.AllowedModels[0]), safe(strings.Join(config.Model.AllowedModels, ",")))
	fmt.Fprintf(w.output, "  Git Gateway: %t (%d remote)\n", len(config.Git.Remotes) > 0, len(config.Git.Remotes))
	for _, remote := range config.Git.Remotes {
		fmt.Fprintf(w.output, "    %s -> %s\n", safe(remote.Name), safe(remote.URL))
	}
	if len(config.Git.Remotes) > 0 {
		fmt.Fprintln(w.output, "    clone/fetch/pullは承認不要、pushはhostで毎回承認")
	}
	resolvedRules, _, resolveErr := projectconfig.ResolveWebRules(config, rules)
	if resolveErr != nil {
		resolvedRules = nil
	}
	fmt.Fprintf(w.output, "  Web Gateway: %t (presets=%s, custom=%d, resolved=%d)\n", config.Web.Enabled, safe(strings.Join(config.Web.OriginPresets, ",")), len(rules), len(resolvedRules))
	for _, rule := range rules {
		fmt.Fprintf(w.output, "    %s\n", formatOrigin(rule))
	}
	fmt.Fprintf(w.output, "  resources: cpu=%d memory=%s disk=%dMiB process=%d open-files=%d\n", config.Resources.CPUs, safe(config.Resources.Memory), config.Resources.DiskBytes>>20, config.Resources.ProcessMax, config.Resources.OpenFileMax)
	fmt.Fprintf(w.output, "  session: ttl=%s idle=%s\n", time.Duration(config.Session.TTLSeconds)*time.Second, time.Duration(config.Session.IdleSeconds)*time.Second)
	fmt.Fprintf(w.output, "  model quota: requests=%d concurrent=%d request=%dMiB response=%dMiB\n", config.Model.MaxRequests, config.Model.MaxConcurrent, config.Model.MaxRequestBytes>>20, config.Model.MaxResponseBytes>>20)
	fmt.Fprintf(w.output, "  export: entries=%d file=%dMiB total=%dMiB; audit=%d日\n", config.Export.MaxEntries, config.Export.MaxFileBytes>>20, config.Export.MaxTotalBytes>>20, config.Audit.RetentionDays)
}

func (w *wizard) yesNo(prompt string, defaultValue bool) (bool, error) {
	suffix := " [y/N]: "
	if defaultValue {
		suffix = " [Y/n]: "
	}
	for {
		line, err := w.line(prompt + suffix)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(line) {
		case "":
			return defaultValue, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(w.output, "y または n を入力してください。")
		}
	}
}

func (w *wizard) choice(prompt string, defaultValue, maximum int) (int, error) {
	for {
		line, err := w.line(fmt.Sprintf("%s [%d]: ", prompt, defaultValue))
		if err != nil {
			return 0, err
		}
		if line == "" {
			return defaultValue, nil
		}
		value, err := strconv.Atoi(line)
		if err == nil && value >= 1 && value <= maximum {
			return value, nil
		}
		fmt.Fprintf(w.output, "1から%dの番号を入力してください。\n", maximum)
	}
}

func (w *wizard) integer(label string, current, minimum, maximum int) (int, error) {
	for {
		line, err := w.line(fmt.Sprintf("%s [%d]: ", label, current))
		if err != nil {
			return 0, err
		}
		if line == "" {
			return current, nil
		}
		value, err := strconv.Atoi(line)
		if err == nil && value >= minimum && value <= maximum {
			return value, nil
		}
		fmt.Fprintf(w.output, "%dから%dの整数を入力してください。\n", minimum, maximum)
	}
}

func (w *wizard) int64(label string, current, minimum, maximum int64) (int64, error) {
	for {
		line, err := w.line(fmt.Sprintf("%s [%d]: ", label, current))
		if err != nil {
			return 0, err
		}
		if line == "" {
			return current, nil
		}
		value, err := strconv.ParseInt(line, 10, 64)
		if err == nil && value >= minimum && value <= maximum {
			return value, nil
		}
		fmt.Fprintf(w.output, "%dから%dの整数を入力してください。\n", minimum, maximum)
	}
}

func (w *wizard) duration(label string, current, minimum, maximum int64) (int64, error) {
	for {
		line, err := w.line(fmt.Sprintf("%s [%s]: ", label, time.Duration(current)*time.Second))
		if err != nil {
			return 0, err
		}
		if line == "" {
			return current, nil
		}
		value, err := time.ParseDuration(line)
		seconds := int64(value / time.Second)
		if err == nil && value == time.Duration(seconds)*time.Second && seconds >= minimum && seconds <= maximum {
			return seconds, nil
		}
		fmt.Fprintf(w.output, "%sから%sの秒単位durationを入力してください（例: 30m, 2h）。\n", time.Duration(minimum)*time.Second, time.Duration(maximum)*time.Second)
	}
}

func (w *wizard) memory(current string) (string, error) {
	for {
		line, err := w.line(fmt.Sprintf("memory上限 [%s]: ", safe(current)))
		if err != nil {
			return "", err
		}
		if line == "" {
			return current, nil
		}
		line = strings.ToUpper(line)
		if len(line) >= 2 && strings.Contains("KMGTP", line[len(line)-1:]) {
			if number, err := strconv.ParseUint(line[:len(line)-1], 10, 64); err == nil && number > 0 {
				return line, nil
			}
		}
		fmt.Fprintln(w.output, "正の整数とK/M/G/T/P単位を入力してください（例: 2G）。")
	}
}

func (w *wizard) requiredLine(prompt string) (string, error) {
	for {
		line, err := w.line(prompt)
		if err != nil {
			return "", err
		}
		if line != "" {
			return line, nil
		}
		fmt.Fprintln(w.output, "空の値は入力できません。")
	}
}

func (w *wizard) line(prompt string) (string, error) {
	if _, err := io.WriteString(w.output, prompt); err != nil {
		return "", err
	}
	if !w.scanner.Scan() {
		if err := w.scanner.Err(); err != nil {
			return "", fmt.Errorf("設定入力を読み取れません: %w", err)
		}
		return "", ErrCanceled
	}
	line := strings.TrimSpace(w.scanner.Text())
	if line == "q" || line == "quit" {
		return "", ErrCanceled
	}
	if !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r\n\t\x1b") {
		return "", fmt.Errorf("設定入力にterminal制御文字は使用できません")
	}
	return line, nil
}

func formatOrigin(rule webgateway.OriginRule) string {
	scheme := "https"
	if rule.AllowHTTP {
		scheme = "http"
	}
	result := scheme + "://" + safe(rule.Host)
	if rule.IncludeSubdomains {
		result += " include-subdomains"
	}
	return result
}

func safe(value string) string { return trustedui.SanitizeTerminal(value) }
