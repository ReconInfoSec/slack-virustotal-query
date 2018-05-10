# slack-virustotal-query
A simple [Lambda](https://console.aws.amazon.com/lambda/home?region=us-east-1#/) function for querying VirusTotal from Slack.

# Instructions
1. Configure a new `/virustotal` [Slash command](https://api.slack.com/slash-commands) in Slack.

2. Make a lambda function with API and add the following Environmental variables:
- `slack_token` = `Slack /slash command token`
- `vt_api` = `VirusTotal API token`

3. Return to kicking ass in the SOC!


# Contributors
- [@eric_capuano](https://twitter.com/eric_capuano)
