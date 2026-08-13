package cli

import (
	"path/filepath"

	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/securefs"
	"sunaba/internal/webgateway"
)

const configPolicyJournalName = ".config-policy-transaction.json"

func configPolicyJournal(projectState string) string {
	return filepath.Join(projectState, configPolicyJournalName)
}

func recoverConfigPolicyTransaction(projectState string) error {
	return securefs.RecoverTransaction(configPolicyJournal(projectState))
}

func persistConfigAndPolicy(configStore *projectconfig.Store, projectState, policyPath string, config projectconfig.Config, rules []webgateway.OriginRule, effective policy.ProjectPolicy) error {
	return persistConfigAndPolicyWithOptions(configStore, projectState, policyPath, config, rules, effective, securefs.TransactionOptions{})
}

func persistConfigAndPolicyWithOptions(configStore *projectconfig.Store, projectState, policyPath string, config projectconfig.Config, rules []webgateway.OriginRule, effective policy.ProjectPolicy, options securefs.TransactionOptions) error {
	policyReplacement, err := policy.PrepareReplacement(policyPath, effective)
	if err != nil {
		return err
	}
	_, replacements, err := configStore.PrepareReplacements(effective.ProjectID, config, rules)
	if err != nil {
		return err
	}
	replacements = append(replacements, policyReplacement)
	return securefs.WriteTransaction(configPolicyJournal(projectState), replacements, options)
}
