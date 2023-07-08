# Certificate Transparency Alerter
This app continuously scanns [Certificate Transparency (CT) logs](https://certificate.transparency.dev/) for customizable keywords, to get alerted when a certificate for your domain is issued. It can also be used to get alerted when someone deploys a new application.

## How to run

I recommend using docker to run this app. 

```bash
docker build . -t janic0/ct_alerter
```
```bash
docker run -d -e PUSHOVER_API_KEY="<pushover-api-key>" -e PUSHOVER_USER_KEY="<pushover-user-key>" -v $PWD:/app janic0/ct_alerter
```
Replace `<pushover-api-key>` and `<pushover-user-key>` with the corresponding values from [Pushover](https://pushover.net/).

## Configuration

There's a volume bound to the local directory in order to sync the `config.yml` file. By default, the configuration will be refreshed from the filesystem every minute. 

This is the format of the `config.yml` file. CloudFlare offers a log of [the most popular CT logs](https://ct.cloudflare.com/logs) here: 

```yaml
logs:
  - https://oak.ct.letsencrypt.org/2022
  - https://oak.ct.letsencrypt.org/2023
  - https://oak.ct.letsencrypt.org/2024h1
  - https://oak.ct.letsencrypt.org/2024h2
  - https://ct.cloudflare.com/logs/nimbus2023
  - https://ct.cloudflare.com/logs/nimbus2024
  - https://ct.cloudflare.com/logs/cirrus
  - https://ct.googleapis.com/logs/xenon2022
  - https://ct.googleapis.com/logs/xenon2023
  - https://ct.googleapis.com/logs/eu1/xenon2024
  - https://nessie2022.ct.digicert.com/log
  - https://nessie2023.ct.digicert.com/log
  - https://nessie2024.ct.digicert.com/log
  - https://nessie2025.ct.digicert.com/log
queries:
  - "janic.io"
  - "google.com"
```

## Modifying the intervals

By default, the app will refetch all entries from the provided logs only every 30 minutes. This is done to reduce bandwith and server load on the log providers, who have to maintain the infrastructure that help to keep the web (at least a bit) more transparent. 
If your use case really needs more frequent refreshes, you can change the intervals in the `main.go` file directly below the imports. 
