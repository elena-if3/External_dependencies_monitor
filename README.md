**Technologies**
Python & relevant libraries – Azure Functions – SonarCloud

**App – once a week**
- Retrieve IP address ranges from Cloudflare
- Compare the IP ranges with those stored in DomainDB, an MSF database hosted on ActivityInfo
- Store the new IP ranges (if any) in DomainDB
- Notify the Infra team about the change by sending an email to the dedicated address using Notification Relay / SendGrid
