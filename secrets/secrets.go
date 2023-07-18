package secrets

import (
	"crypto/sha1"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Secrets struct {
	rules    map[string]config.Rule
	detector detect.Detector
}

type Rule struct {
	Rule config.Rule
	Tags []string
}

const TagApiKey = "api-key"
const TagClientId = "client-id"
const TagClientSecret = "client-secret"
const TagSecretKey = "secret-key"
const TagAccessKey = "access-key"
const TagAccessId = "access-id"
const TagApiToken = "api-token"
const TagAccessToken = "access-token"
const TagRefreshToken = "refresh-token"
const TagPrivateKey = "private-key"
const TagPublicKey = "public-key"
const TagEncryptionKey = "encryption-key"
const TagTriggerToken = "trigger-token"
const TagRegistrationToken = "registration-token"
const TagPassword = "password"
const TagUploadToken = "upload-token"
const TagPublicSecret = "public-secret"
const TagSensitiveUrl = "sensitive-url"
const TagWebhook = "webhook"

const customRegexRuleIdFormat = "custom-regex-%d"

func Init(includeList, excludeList []string) (*Secrets, error) {
	if len(includeList) > 0 && len(excludeList) > 0 {
		return nil, fmt.Errorf("cannot use both include and exclude flags")
	}

	allRules, _ := loadAllRules()
	rulesToBeApplied := make(map[string]config.Rule)
	if len(includeList) > 0 {
		rulesToBeApplied = selectRules(allRules, includeList)
	} else if len(excludeList) > 0 {
		rulesToBeApplied = excludeRules(allRules, excludeList)
	} else {
		for _, rule := range allRules {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	}
	if len(rulesToBeApplied) == 0 {
		return nil, fmt.Errorf("no rules were selected")
	}

	config := config.Config{
		Rules: rulesToBeApplied,
	}

	detector := detect.NewDetector(config)

	return &Secrets{
		rules:    rulesToBeApplied,
		detector: *detector,
	}, nil
}

func (s *Secrets) Detect(item plugins.Item, secretsChannel chan reporting.Secret, wg *sync.WaitGroup, ignoredIds []string) {
	defer wg.Done()

	fragment := detect.Fragment{
		Raw: item.Content,
	}
	for _, value := range s.detector.Detect(fragment) {
		itemId := getFindingId(item, value)
		secret := reporting.Secret{
			ID:          itemId,
			Source:      item.Source,
			RuleID:      value.RuleID,
			StartLine:   value.StartLine,
			StartColumn: value.StartColumn,
			EndLine:     value.EndLine,
			EndColumn:   value.EndColumn,
			Value:       value.Secret,
		}
		if !isSecretIgnored(&secret, &ignoredIds) {
			secretsChannel <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
	}
}

func (s *Secrets) AddRegexRules(patterns []string) error {
	for idx, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile regex rule %s: %w", pattern, err)
		}
		rule := config.Rule{
			Description: "Custom Regex Rule From User",
			RuleID:      fmt.Sprintf(customRegexRuleIdFormat, idx+1),
			Regex:       regex,
			Keywords:    []string{},
		}
		s.rules[rule.RuleID] = rule
	}
	return nil
}

func getFindingId(item plugins.Item, finding report.Finding) string {
	idParts := []string{item.ID, finding.RuleID, finding.Secret}
	sha := sha1.Sum([]byte(strings.Join(idParts, "-")))
	return fmt.Sprintf("%x", sha)
}

func isSecretIgnored(secret *reporting.Secret, ignoredIds *[]string) bool {
	for _, ignoredId := range *ignoredIds {
		if secret.ID == ignoredId {
			return true
		}
	}
	return false
}

func selectRules(allRules []Rule, tags []string) map[string]config.Rule {
	rulesToBeApplied := make(map[string]config.Rule)

	for _, rule := range allRules {
		if isRuleMatch(rule, tags) {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	}
	return rulesToBeApplied
}

func excludeRules(allRules []Rule, tags []string) map[string]config.Rule {
	rulesToBeApplied := make(map[string]config.Rule)

	for _, rule := range allRules {
		if !isRuleMatch(rule, tags) {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	}
	return rulesToBeApplied
}

func isRuleMatch(rule Rule, tags []string) bool {
	for _, tag := range tags {
		if strings.EqualFold(rule.Rule.RuleID, tag) {
			return true
		}
		for _, ruleTag := range rule.Tags {
			if strings.EqualFold(ruleTag, tag) {
				return true
			}
		}
	}
	return false
}

func getRules(allRules []Rule, tags []string) map[string]config.Rule {
	rulesToBeApplied := make(map[string]config.Rule)

	if isAllFilter(tags) {
		// ensure rules have unique ids
		for _, rule := range allRules {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	} else {
		for _, rule := range allRules {
			rule.Rule.Keywords = []string{}
			for _, userTag := range tags {
				for _, ruleTag := range rule.Tags {
					if strings.EqualFold(ruleTag, userTag) {
						rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
					}
				}
			}
		}
	}
	return rulesToBeApplied
}

func isAllFilter(rulesFilter []string) bool {
	for _, filter := range rulesFilter {
		if strings.EqualFold(filter, "all") {
			return true
		}
	}
	return false
}

func loadAllRules() ([]Rule, error) {
	allRules := []Rule{
		{Rule: *rules.AdafruitAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.AdafruitAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.AdobeClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.AdobeClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.AgeSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.Airtable(), Tags: []string{TagApiKey}},
		{Rule: *rules.AlgoliaApiKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.AlibabaAccessKey(), Tags: []string{TagAccessKey, TagAccessId}},
		{Rule: *rules.AlibabaSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.AsanaClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.AsanaClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.Atlassian(), Tags: []string{TagApiToken}},
		{Rule: *rules.AWS(), Tags: []string{TagAccessToken}},
		{Rule: *rules.BitBucketClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.BitBucketClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.BittrexAccessKey(), Tags: []string{TagAccessKey}},
		{Rule: *rules.BittrexSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.Beamer(), Tags: []string{TagApiToken}},
		{Rule: *rules.CodecovAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.CoinbaseAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Clojars(), Tags: []string{TagApiToken}},
		{Rule: *rules.ConfluentAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ConfluentSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.Contentful(), Tags: []string{TagApiToken}},
		{Rule: *rules.Databricks(), Tags: []string{TagApiToken}},
		{Rule: *rules.DatadogtokenAccessToken(), Tags: []string{TagAccessToken, TagClientId}},
		{Rule: *rules.DigitalOceanPAT(), Tags: []string{TagAccessToken}},
		{Rule: *rules.DigitalOceanOAuthToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.DigitalOceanRefreshToken(), Tags: []string{TagRefreshToken}},
		{Rule: *rules.DiscordAPIToken(), Tags: []string{TagApiKey, TagApiToken}},
		{Rule: *rules.DiscordClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.DiscordClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.Doppler(), Tags: []string{TagApiToken}},
		{Rule: *rules.DropBoxAPISecret(), Tags: []string{TagApiToken}},
		{Rule: *rules.DropBoxShortLivedAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.DropBoxLongLivedAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.DroneciAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Duffel(), Tags: []string{TagApiToken}},
		{Rule: *rules.Dynatrace(), Tags: []string{TagApiToken}},
		{Rule: *rules.EasyPost(), Tags: []string{TagApiToken}},
		{Rule: *rules.EasyPostTestAPI(), Tags: []string{TagApiToken}},
		{Rule: *rules.EtsyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Facebook(), Tags: []string{TagApiToken}},
		{Rule: *rules.FastlyAPIToken(), Tags: []string{TagApiToken, TagApiKey}},
		{Rule: *rules.FinicityClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.FinicityAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.FlickrAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.FinnhubAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.FlutterwavePublicKey(), Tags: []string{TagPublicKey}},
		{Rule: *rules.FlutterwaveSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.FlutterwaveEncKey(), Tags: []string{TagEncryptionKey}},
		{Rule: *rules.FrameIO(), Tags: []string{TagApiToken}},
		{Rule: *rules.FreshbooksAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GCPAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.GenericCredential(), Tags: []string{TagApiKey}},
		{Rule: *rules.GitHubPat(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubFineGrainedPat(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubOauth(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubApp(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubRefresh(), Tags: []string{TagRefreshToken}},
		{Rule: *rules.GitlabPat(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitlabPipelineTriggerToken(), Tags: []string{TagTriggerToken}},
		{Rule: *rules.GitlabRunnerRegistrationToken(), Tags: []string{TagRegistrationToken}},
		{Rule: *rules.GitterAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GoCardless(), Tags: []string{TagApiToken}},
		{Rule: *rules.GrafanaApiKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.GrafanaCloudApiToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.GrafanaServiceAccountToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Hashicorp(), Tags: []string{TagApiToken}},
		{Rule: *rules.Heroku(), Tags: []string{TagApiKey}},
		{Rule: *rules.HubSpot(), Tags: []string{TagApiToken, TagApiKey}},
		{Rule: *rules.Intercom(), Tags: []string{TagApiToken, TagApiKey}},
		// TODO: Add JFROG when it will be released https://github.com/gitleaks/gitleaks/pull/1233
		{Rule: *rules.JWT(), Tags: []string{TagAccessToken}},
		{Rule: *rules.KrakenAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.KucoinAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.KucoinSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.LaunchDarklyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.LinearAPIToken(), Tags: []string{TagApiToken, TagApiKey}},
		{Rule: *rules.LinearClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.LinkedinClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.LinkedinClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.LobAPIToken(), Tags: []string{TagApiKey}},
		{Rule: *rules.LobPubAPIToken(), Tags: []string{TagApiKey}},
		{Rule: *rules.MailChimp(), Tags: []string{TagApiKey}},
		{Rule: *rules.MailGunPubAPIToken(), Tags: []string{TagPublicKey}},
		{Rule: *rules.MailGunPrivateAPIToken(), Tags: []string{TagPrivateKey}},
		{Rule: *rules.MailGunSigningKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.MapBox(), Tags: []string{TagApiToken}},
		{Rule: *rules.MattermostAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.MessageBirdAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.MessageBirdClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.NetlifyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.NewRelicUserID(), Tags: []string{TagApiKey}},
		{Rule: *rules.NewRelicUserKey(), Tags: []string{TagAccessId}},
		{Rule: *rules.NewRelicBrowserAPIKey(), Tags: []string{TagApiToken}},
		{Rule: *rules.NPM(), Tags: []string{TagAccessToken}},
		{Rule: *rules.NytimesAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.OktaAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.PlaidAccessID(), Tags: []string{TagClientId}},
		{Rule: *rules.PlaidSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.PlaidAccessToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.PlanetScalePassword(), Tags: []string{TagPassword}},
		{Rule: *rules.PlanetScaleAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.PlanetScaleOAuthToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.PostManAPI(), Tags: []string{TagApiToken}},
		{Rule: *rules.Prefect(), Tags: []string{TagApiToken}},
		{Rule: *rules.PrivateKey(), Tags: []string{TagPrivateKey}},
		{Rule: *rules.PulumiAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.PyPiUploadToken(), Tags: []string{TagUploadToken}},
		{Rule: *rules.RapidAPIAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ReadMe(), Tags: []string{TagApiToken}},
		{Rule: *rules.RubyGemsAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.SendbirdAccessID(), Tags: []string{TagAccessId}},
		{Rule: *rules.SendbirdAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SendGridAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.SendInBlueAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.SentryAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShippoAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.ShopifyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShopifyCustomAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShopifyPrivateAppAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShopifySharedSecret(), Tags: []string{TagPublicSecret}},
		{Rule: *rules.SidekiqSecret(), Tags: []string{TagSecretKey}},
		{Rule: *rules.SidekiqSensitiveUrl(), Tags: []string{TagSensitiveUrl}},
		{Rule: *rules.SlackAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackWebHook(), Tags: []string{TagWebhook}},
		{Rule: *rules.StripeAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SquareAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SquareSpaceAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SumoLogicAccessID(), Tags: []string{TagAccessId}},
		{Rule: *rules.SumoLogicAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.TeamsWebhook(), Tags: []string{TagWebhook}},
		{Rule: *rules.TelegramBotToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.TravisCIAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Twilio(), Tags: []string{TagApiKey}},
		{Rule: *rules.TwitchAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.TwitterAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.TwitterAPISecret(), Tags: []string{TagApiKey}},
		{Rule: *rules.TwitterAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.TwitterAccessSecret(), Tags: []string{TagPublicSecret}},
		{Rule: *rules.TwitterBearerToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.Typeform(), Tags: []string{TagApiToken}},
		{Rule: *rules.VaultBatchToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.VaultServiceToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.YandexAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.YandexAWSAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.YandexAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ZendeskSecretKey(), Tags: []string{TagSecretKey}},
	}
	return allRules, nil
}

var RulesCommand = &cobra.Command{
	Use:   "rules",
	Short: "List all rules",
	Long:  `List all rules`,
	RunE: func(cmd *cobra.Command, args []string) error {

		rules, err := loadAllRules()
		if err != nil {
			return err
		}

		tab := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)

		fmt.Fprintln(tab, "Name\tDescription\tTags")
		fmt.Fprintln(tab, "----\t----\t----")
		for _, rule := range rules {
			fmt.Fprintf(tab, "%s\t%s\t%s\n", rule.Rule.RuleID, rule.Rule.Description, strings.Join(rule.Tags, ","))
		}
		if err = tab.Flush(); err != nil {
			return err
		}

		return nil
	},
}
