export type Remediation = {
  revokeUrl: string
  steps: string[]
}

const remediations: Record<string, Remediation> = {
  'OpenAI API Key': {
    revokeUrl: 'https://platform.openai.com/api-keys',
    steps: [
      'Revoke the key in the OpenAI dashboard immediately',
      'Create a replacement key and update secrets storage only',
      'Check usage logs for unexpected calls after the leak time',
    ],
  },
  'OpenAI Project Key': {
    revokeUrl: 'https://platform.openai.com/api-keys',
    steps: [
      'Revoke the project key in the OpenAI dashboard',
      'Rotate any dependent services to a new key',
      'Review project usage for abuse',
    ],
  },
  'OpenAI Service Account Key': {
    revokeUrl: 'https://platform.openai.com/api-keys',
    steps: [
      'Revoke the service account key',
      'Issue a new key into your secret manager',
      'Audit recent API usage for that account',
    ],
  },
  'Anthropic API Key': {
    revokeUrl: 'https://console.anthropic.com/settings/keys',
    steps: [
      'Delete or rotate the key in the Anthropic console',
      'Update deployments with the new key',
      'Review usage for unexpected traffic',
    ],
  },
  'Groq API Key': {
    revokeUrl: 'https://console.groq.com/keys',
    steps: ['Revoke the Groq key', 'Create a new key in your secret store'],
  },
  'Replicate API Token': {
    revokeUrl: 'https://replicate.com/account/api-tokens',
    steps: ['Revoke the Replicate token', 'Issue a replacement token'],
  },
  'AWS Access Key': {
    revokeUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    steps: [
      'Deactivate and delete the access key in IAM',
      'Create a new key or switch to a role',
      'Check CloudTrail for API calls using the leaked key',
    ],
  },
  'AWS Temporary Access Key': {
    revokeUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    steps: [
      'Invalidate the session if still active',
      'Rotate long-lived credentials that minted this key',
      'Review CloudTrail for the session window',
    ],
  },
  'AWS Secret Key': {
    revokeUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    steps: [
      'Delete the matching access key pair in IAM',
      'Rotate any services that used this secret',
      'Audit CloudTrail for suspicious activity',
    ],
  },
  'GitHub Personal Access Token': {
    revokeUrl: 'https://github.com/settings/tokens',
    steps: [
      'Revoke the token under Developer settings',
      'Create a fine-grained replacement with least privilege',
      'Check security log for unexpected access',
    ],
  },
  'GitHub Fine-Grained Token': {
    revokeUrl: 'https://github.com/settings/personal-access-tokens',
    steps: [
      'Revoke the fine-grained token',
      'Reissue with minimal repository and permission scope',
      'Review org/user security logs',
    ],
  },
  'GitHub App Token': {
    revokeUrl: 'https://github.com/settings/apps',
    steps: [
      'Rotate the GitHub App private key or revoke installations',
      'Regenerate secrets for the app',
      'Review app installation audit events',
    ],
  },
  'GitHub OAuth Token': {
    revokeUrl: 'https://github.com/settings/applications',
    steps: [
      'Revoke the OAuth authorization',
      'Rotate the OAuth app client secret if exposed',
      'Review authorized apps for the account',
    ],
  },
  'Stripe Live Secret Key': {
    revokeUrl: 'https://dashboard.stripe.com/apikeys',
    steps: [
      'Roll the live secret key in the Stripe dashboard',
      'Update servers with the new secret immediately',
      'Review payouts and API logs for fraud',
    ],
  },
  'Stripe Restricted Key': {
    revokeUrl: 'https://dashboard.stripe.com/apikeys',
    steps: [
      'Delete the restricted key',
      'Create a new restricted key with least privilege',
      'Check Stripe logs for unexpected calls',
    ],
  },
  'Stripe Webhook Secret': {
    revokeUrl: 'https://dashboard.stripe.com/webhooks',
    steps: [
      'Roll the webhook signing secret',
      'Update endpoint verification config',
      'Confirm webhooks still verify after rotation',
    ],
  },
  'Stripe Live Publishable Key': {
    revokeUrl: 'https://dashboard.stripe.com/apikeys',
    steps: [
      'Publishable keys are public by design but still roll if abused',
      'Restrict allowed domains in Stripe settings',
      'Monitor for unexpected client-side usage',
    ],
  },
  'Slack Bot Token': {
    revokeUrl: 'https://api.slack.com/apps',
    steps: ['Reinstall or rotate the bot token for the Slack app', 'Update the token in secret storage'],
  },
  'Slack User Token': {
    revokeUrl: 'https://api.slack.com/apps',
    steps: ['Revoke the user token', 'Re-authorize with minimal scopes'],
  },
  'Slack App Token': {
    revokeUrl: 'https://api.slack.com/apps',
    steps: ['Rotate the app-level token', 'Update socket mode or app config'],
  },
  'Slack Webhook URL': {
    revokeUrl: 'https://api.slack.com/apps',
    steps: ['Disable or regenerate the incoming webhook', 'Update callers to the new URL'],
  },
  'Discord Bot Token': {
    revokeUrl: 'https://discord.com/developers/applications',
    steps: ['Reset the bot token in the Discord developer portal', 'Update the bot process with the new token'],
  },
  'Discord Webhook URL': {
    revokeUrl: 'https://discord.com/developers/docs/resources/webhook',
    steps: ['Delete the webhook in channel settings', 'Create a new webhook if still needed'],
  },
  'Telegram Bot Token': {
    revokeUrl: 'https://my.telegram.org',
    steps: ['Revoke the bot token via BotFather (/revoke)', 'Update services with the new token'],
  },
  'SendGrid API Key': {
    revokeUrl: 'https://app.sendgrid.com/settings/api_keys',
    steps: ['Delete the SendGrid API key', 'Create a replacement key with least privilege'],
  },
  'Mailgun API Key': {
    revokeUrl: 'https://app.mailgun.com/',
    steps: ['Rotate the Mailgun API key', 'Update sending services'],
  },
  'Mailchimp API Key': {
    revokeUrl: 'https://admin.mailchimp.com/account/api/',
    steps: ['Disable the API key', 'Create a new key and update integrations'],
  },
  'Resend API Key': {
    revokeUrl: 'https://resend.com/api-keys',
    steps: ['Delete the Resend API key', 'Create a new key in secret storage'],
  },
  'Postmark Server Token': {
    revokeUrl: 'https://account.postmarkapp.com/servers',
    steps: ['Rotate the server API token', 'Update transactional email config'],
  },
  'npm Access Token': {
    revokeUrl: 'https://www.npmjs.com/settings/~/tokens',
    steps: [
      'Revoke the npm token',
      'Create a granular token with publish-only where needed',
      'Check for unexpected publishes',
    ],
  },
  'Google API Key': {
    revokeUrl: 'https://console.cloud.google.com/apis/credentials',
    steps: [
      'Restrict or delete the API key',
      'Add application and API restrictions before reuse',
      'Review quota usage for abuse',
    ],
  },
  'Database URL (PostgreSQL)': {
    revokeUrl: 'https://www.postgresql.org/docs/current/sql-alterrole.html',
    steps: [
      'Rotate the database password immediately',
      'Update connection strings in secret managers only',
      'Review DB logs for unexpected connections',
    ],
  },
  'Database URL (MySQL)': {
    revokeUrl: 'https://dev.mysql.com/doc/refman/8.0/en/alter-user.html',
    steps: [
      'Rotate the MySQL user password',
      'Update application connection strings',
      'Review access logs',
    ],
  },
  'Database URL (MongoDB)': {
    revokeUrl: 'https://www.mongodb.com/docs/manual/core/authentication/',
    steps: [
      'Rotate the MongoDB user password',
      'Update URI secrets in all environments',
      'Review atlas/cluster access logs if applicable',
    ],
  },
  'Database URL (Redis)': {
    revokeUrl: 'https://redis.io/docs/management/security/',
    steps: [
      'Rotate the Redis password / ACL secret',
      'Update connection URLs',
      'Flush or audit suspicious keys if exposed publicly',
    ],
  },
  'AMQP URL': {
    revokeUrl: 'https://www.rabbitmq.com/docs/access-control',
    steps: [
      'Rotate broker credentials',
      'Update AMQP URLs in secret storage',
      'Review broker connection logs',
    ],
  },
  'RSA Private Key': {
    revokeUrl: 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh',
    steps: [
      'Treat the key as compromised and stop using it',
      'Generate a new key pair and replace authorized keys',
      'Revoke the public key everywhere it was installed',
    ],
  },
  'EC Private Key': {
    revokeUrl: 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh',
    steps: [
      'Stop using the leaked key',
      'Generate a replacement key pair',
      'Remove the old public key from servers and Git hosts',
    ],
  },
  'OpenSSH Private Key': {
    revokeUrl: 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh',
    steps: [
      'Remove the public key from authorized_keys and Git hosts',
      'Generate a new SSH key',
      'Audit login logs for the old key fingerprint',
    ],
  },
  'PGP Private Key': {
    revokeUrl: 'https://www.ietf.org/rfc/rfc4880.txt',
    steps: [
      'Publish a revocation certificate for the key',
      'Generate a new PGP key if still needed',
      'Notify contacts who trusted the old key',
    ],
  },
  'PKCS8 Private Key': {
    revokeUrl: 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh',
    steps: [
      'Stop using the private key',
      'Rotate certificates or SSH identities that used it',
      'Remove distributed public material',
    ],
  },
  'DSA Private Key': {
    revokeUrl: 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh',
    steps: [
      'Retire the DSA key (also prefer migrating off DSA)',
      'Replace with a modern key type',
      'Revoke old authorized keys',
    ],
  },
  'GitLab Personal Access Token': {
    revokeUrl: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    steps: ['Revoke the GitLab PAT', 'Create a replacement with least scopes'],
  },
  'GitLab Runner Token': {
    revokeUrl: 'https://docs.gitlab.com/runner/security/',
    steps: ['Reset the runner authentication token', 'Re-register the runner if required'],
  },
  'GitLab Deploy Token': {
    revokeUrl: 'https://docs.gitlab.com/user/project/deploy_tokens/',
    steps: ['Revoke the deploy token in project settings', 'Create a new deploy token'],
  },
  'GitLab OAuth App Secret': {
    revokeUrl: 'https://gitlab.com/oauth/applications',
    steps: ['Rotate the OAuth application secret', 'Update dependent apps'],
  },
  'Twilio Account SID': {
    revokeUrl: 'https://console.twilio.com/',
    steps: [
      'SID alone is less sensitive than the auth token but still restrict exposure',
      'Rotate the auth token if it may also be leaked',
      'Review Twilio debugger for abuse',
    ],
  },
  'Twilio Auth Token': {
    revokeUrl: 'https://console.twilio.com/',
    steps: ['Rotate the auth token in Twilio console', 'Update API clients', 'Review call/SMS logs'],
  },
  'HuggingFace Access Token': {
    revokeUrl: 'https://huggingface.co/settings/tokens',
    steps: ['Revoke the Hugging Face token', 'Create a fine-grained replacement'],
  },
  'Vercel Access Token': {
    revokeUrl: 'https://vercel.com/account/tokens',
    steps: ['Delete the Vercel token', 'Create a new token with least scope'],
  },
  'Supabase Service Role Key': {
    revokeUrl: 'https://supabase.com/dashboard/project/_/settings/api',
    steps: [
      'Rotate the service role key immediately',
      'Never expose service role keys to clients',
      'Audit database and storage access',
    ],
  },
  'Cloudflare API Token': {
    revokeUrl: 'https://dash.cloudflare.com/profile/api-tokens',
    steps: ['Roll the API token', 'Create a scoped replacement token'],
  },
  'Cloudflare Global API Key': {
    revokeUrl: 'https://dash.cloudflare.com/profile/api-tokens',
    steps: [
      'Change the global API key password flow / regenerate',
      'Prefer scoped API tokens going forward',
      'Review account audit logs',
    ],
  },
  'Azure Storage Connection String': {
    revokeUrl: 'https://portal.azure.com/',
    steps: [
      'Rotate storage account access keys',
      'Update connection strings in Key Vault',
      'Review storage analytics for unexpected access',
    ],
  },
  'Azure Client Secret': {
    revokeUrl: 'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade',
    steps: [
      'Delete the leaked client secret in App registrations',
      'Create a new secret or switch to federated credentials',
      'Review Entra sign-in logs',
    ],
  },
  'Firebase Service Account Key': {
    revokeUrl: 'https://console.firebase.google.com/',
    steps: [
      'Disable or delete the service account key in Google Cloud IAM',
      'Create a new key only if required',
      'Review IAM and Firebase audit logs',
    ],
  },
  'Firebase Web API Key': {
    revokeUrl: 'https://console.firebase.google.com/',
    steps: [
      'Restrict the browser key by HTTP referrer',
      'Rotate if abuse is confirmed',
      'Tighten Firebase Security Rules',
    ],
  },
  'PyPI API Token': {
    revokeUrl: 'https://pypi.org/manage/account/token/',
    steps: ['Revoke the PyPI token', 'Create a project-scoped replacement'],
  },
  'Doppler Service Token': {
    revokeUrl: 'https://dashboard.doppler.com/',
    steps: ['Revoke the service token', 'Issue a new token into the runtime'],
  },
  'Doppler Personal Token': {
    revokeUrl: 'https://dashboard.doppler.com/workplace/tokens',
    steps: ['Revoke the personal token', 'Create a replacement with least access'],
  },
  'DigitalOcean Personal Access Token': {
    revokeUrl: 'https://cloud.digitalocean.com/account/api/tokens',
    steps: ['Revoke the DigitalOcean token', 'Create a scoped replacement'],
  },
  'DigitalOcean OAuth Token': {
    revokeUrl: 'https://cloud.digitalocean.com/account/api/tokens',
    steps: ['Revoke the OAuth token', 'Re-authorize the integration'],
  },
  'Netlify Access Token': {
    revokeUrl: 'https://app.netlify.com/user/applications',
    steps: ['Revoke the Netlify access token', 'Create a new personal access token'],
  },
  'PlanetScale Token': {
    revokeUrl: 'https://app.planetscale.com/',
    steps: ['Revoke the PlanetScale token', 'Create a new service token'],
  },
  'Terraform Cloud Token': {
    revokeUrl: 'https://app.terraform.io/app/settings/tokens',
    steps: ['Revoke the Terraform Cloud token', 'Create a new API token'],
  },
  'Pulumi Access Token': {
    revokeUrl: 'https://app.pulumi.com/account/tokens',
    steps: ['Revoke the Pulumi access token', 'Create a replacement token'],
  },
  'HashiCorp Vault Token': {
    revokeUrl: 'https://developer.hashicorp.com/vault/docs/concepts/tokens',
    steps: [
      'Revoke the Vault token via vault token revoke',
      'Issue a new token with least policies',
      'Audit Vault access logs',
    ],
  },
  'Sentry Auth Token': {
    revokeUrl: 'https://sentry.io/settings/account/api/auth-tokens/',
    steps: ['Revoke the Sentry auth token', 'Create a new token with minimal scopes'],
  },
  'Sentry DSN': {
    revokeUrl: 'https://sentry.io/settings/',
    steps: [
      'Rotate the client key / DSN if abused for event spam',
      'Tighten allowed domains',
      'Review inbound event volume',
    ],
  },
  'New Relic User API Key': {
    revokeUrl: 'https://one.newrelic.com/api-keys',
    steps: ['Delete the user API key', 'Create a replacement key'],
  },
  'New Relic License Key': {
    revokeUrl: 'https://one.newrelic.com/api-keys',
    steps: ['Rotate the license key', 'Update agents with the new key'],
  },
  'Datadog API Key': {
    revokeUrl: 'https://app.datadoghq.com/organization-settings/api-keys',
    steps: ['Disable the Datadog API key', 'Create a new key and update agents'],
  },
  'Notion Integration Token': {
    revokeUrl: 'https://www.notion.so/my-integrations',
    steps: ['Reset the integration secret', 'Update automation that used the token'],
  },
  'Linear API Key': {
    revokeUrl: 'https://linear.app/settings/api',
    steps: ['Revoke the Linear API key', 'Create a new personal API key'],
  },
  'Postman API Key': {
    revokeUrl: 'https://postman.co/settings/me/api-keys',
    steps: ['Delete the Postman API key', 'Create a replacement key'],
  },
  'Dropbox Access Token': {
    revokeUrl: 'https://www.dropbox.com/account/connected_apps',
    steps: ['Revoke the Dropbox app authorization', 'Re-issue a token if required'],
  },
  'Mapbox Secret Token': {
    revokeUrl: 'https://account.mapbox.com/access-tokens/',
    steps: ['Delete the secret token', 'Create a scoped public/secret token pair as needed'],
  },
  'Algolia API Key': {
    revokeUrl: 'https://www.algolia.com/account/api-keys/',
    steps: [
      'Revoke the Admin/write key if leaked',
      'Prefer search-only keys on clients',
      'Create a replacement with least ACL',
    ],
  },
  'Contentful Access Token': {
    revokeUrl: 'https://app.contentful.com/',
    steps: ['Revoke the Contentful token', 'Create a new API key in space settings'],
  },
  'Heroku API Key': {
    revokeUrl: 'https://dashboard.heroku.com/account',
    steps: ['Regenerate the Heroku API key', 'Update CI and CLI configs'],
  },
  'GCP Service Account Email': {
    revokeUrl: 'https://console.cloud.google.com/iam-admin/serviceaccounts',
    steps: [
      'Email alone is not a secret but may indicate a leaked key file nearby',
      'Rotate service account keys for that account',
      'Review IAM key usage',
    ],
  },
  'Shopify Access Token': {
    revokeUrl: 'https://admin.shopify.com/',
    steps: ['Revoke the Admin API access token', 'Reinstall or recreate the custom app token'],
  },
  'Shopify Shared Secret': {
    revokeUrl: 'https://admin.shopify.com/',
    steps: ['Rotate the app shared secret', 'Update webhook verification'],
  },
  'Shopify Custom App Token': {
    revokeUrl: 'https://admin.shopify.com/',
    steps: ['Revoke the custom app token', 'Create a new token with least scopes'],
  },
  'Shopify Private App Token': {
    revokeUrl: 'https://admin.shopify.com/',
    steps: ['Disable the private app credentials', 'Migrate to a custom app with a new token'],
  },
  'Square Access Token': {
    revokeUrl: 'https://developer.squareup.com/apps',
    steps: ['Revoke the Square access token', 'Generate a new production token'],
  },
  'Square OAuth Secret': {
    revokeUrl: 'https://developer.squareup.com/apps',
    steps: ['Rotate the OAuth application secret', 'Update OAuth clients'],
  },
  'Generic API Key': {
    revokeUrl: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key',
    steps: [
      'Identify the provider from context and revoke there',
      'Move the value into a secret manager',
      'Purge it from git history if it was committed',
    ],
  },
  'JWT Token': {
    revokeUrl: 'https://jwt.io/introduction',
    steps: [
      'Invalidate sessions or rotate signing secrets for the issuer',
      'Treat long-lived JWTs as compromised',
      'Review auth logs around the leak time',
    ],
  },
  'SSN': {
    revokeUrl: 'https://www.identitytheft.gov/',
    steps: [
      'Treat as a privacy incident',
      'Remove the value from source and history',
      'Follow your org incident response for PII exposure',
    ],
  },
  'Credit Card': {
    revokeUrl: 'https://www.pcisecuritystandards.org/',
    steps: [
      'Treat as a PCI incident',
      'Remove card data from source control immediately',
      'Notify your payment provider / compliance contact',
    ],
  },
  'Email Address': {
    revokeUrl: 'https://www.ftc.gov/business-guidance/privacy-security',
    steps: [
      'Confirm whether the email is production PII or a fixture',
      'Remove real addresses from source if not required',
      'Prefer synthetic data in tests',
    ],
  },
  'Phone Number (US)': {
    revokeUrl: 'https://www.ftc.gov/business-guidance/privacy-security',
    steps: [
      'Remove real phone numbers from source when possible',
      'Use fictional 555 numbers in fixtures',
      'Follow PII incident process if production data leaked',
    ],
  },
  'Phone Number (International)': {
    revokeUrl: 'https://www.ftc.gov/business-guidance/privacy-security',
    steps: [
      'Remove real phone numbers from source when possible',
      'Use synthetic numbers in tests',
      'Follow PII incident process if production data leaked',
    ],
  },
  'IPv4 Address': {
    revokeUrl: 'https://owasp.org/www-community/vulnerabilities/Information_leakage',
    steps: [
      'Confirm whether the IP is sensitive infrastructure',
      'Remove internal IPs from public repos when possible',
      'Rotate access controls if a private endpoint was exposed',
    ],
  },
}

/**
 * Look up revoke guidance for a detector name.
 */
export function getRemediation(patternName: string): Remediation | undefined {
  return remediations[patternName]
}
