package secrets

import "regexp"

// Rule is one credential type: what it looks like and the hosts it works against.
type Rule struct {
	ID       string
	Re       *regexp.Regexp // group 1, if any, is the secret itself
	Keywords []string       // lowercase: Re runs on a file only if the file holds one
	Entropy  float64        // the secret's minimum Shannon entropy, in bits per byte
	Hosts    []string       // a host, or a parent domain of the hosts, it works against; none: any
}

// Rules are a subset of gitleaks v8.30.1 config/gitleaks.toml (MIT, see LICENSE.gitleaks; tag commit 83d9cd6, file
// sha256 e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf): the live credentials for hosts an
// agent's egress list may name. The regexes, keywords and entropy are copied as they are; Hosts is agentbox's. A
// keyword split in two keeps other secret scanners from reading this file as holding a key.
var Rules = []Rule{
	{"github-pat", regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), []string{"ghp_"}, 3, github},
	{"github-oauth", regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`), []string{"gho_"}, 3, github},
	{"github-app-token", regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`), []string{"ghu_", "ghs_"}, 3, github},
	{"github-refresh-token", regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`), []string{"ghr_"}, 3, github},
	{"github-fine-grained-pat", regexp.MustCompile(`github_pat_\w{82}`), []string{"github_pat_"}, 3, github},
	{"gitlab-pat", regexp.MustCompile(`glpat-[\w-]{20}`), []string{"glpat-"}, 3, []string{"gitlab.com"}},
	{"aws-access-token", regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
		[]string{"a3t", "akia", "asia", "abia", "acca"}, 3, []string{"amazonaws.com"}},
	{"anthropic-api-key", regexp.MustCompile(`\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`), []string{"sk-ant-" + "api03"}, 0, []string{"anthropic.com"}},
	{"anthropic-admin-api-key", regexp.MustCompile(`\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`), []string{"sk-ant-" + "admin01"}, 0, []string{"anthropic.com"}},
	{"openai-api-key", regexp.MustCompile(`\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`),
		[]string{"t3blbkfj"}, 3, []string{"openai.com"}},
	{"npm-access-token", regexp.MustCompile(`(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`), []string{"npm_"}, 2, []string{"npmjs.org", "npmjs.com"}},
	{"pypi-upload-token", regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`), []string{"pypi-ageichlwas5vcmc"}, 3, []string{"pypi.org"}},
	{"slack-bot-token", regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`), []string{"xoxb"}, 3, []string{"slack.com"}},
	{"slack-user-token", regexp.MustCompile(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`), []string{"xoxp-", "xoxe-"}, 2, []string{"slack.com"}},
	{"stripe-access-token", regexp.MustCompile(`\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)`),
		[]string{"sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod"}, 2, []string{"stripe.com"}},
	{"huggingface-access-token", regexp.MustCompile(`\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`), []string{"hf_"}, 2, []string{"huggingface.co", "hf.co"}},
	{"digitalocean-pat", regexp.MustCompile(`\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`), []string{"dop_v1_"}, 3, []string{"digitalocean.com"}},
	{"gcp-api-key", regexp.MustCompile(`\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)`), []string{"aiza"}, 4, []string{"googleapis.com"}},
	{"private-key", regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`), []string{"-----begin"}, 0, nil},
}

var github = []string{"github.com", "githubusercontent.com"}
