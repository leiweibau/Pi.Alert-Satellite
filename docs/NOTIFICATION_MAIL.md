## Configure Mail Notification

You can also activate an email notification from the satellite. However, this is only triggered if a previously configured 
threshold (`COLLECT_REPORTS_FOR_MAIL`) of consecutive faulty transmissions has been reached. When the threshold is exceeded, 
the log files collected up to that point are attached to the email and sent to the destination address. No further 
notifications are sent. Only when a scan has been successfully transmitted is a new notification possible when the configured 
threshold is reached.

```
# Mail-Account Settings
# ----------------------
SMTP_SERVER                = 'smtp.gmail.com'
SMTP_PORT                  = 587
SMTP_USER                  = 'user@gmail.com'
SMTP_PASS                  = 'password'
SMTP_SKIP_TLS	           = False
SMTP_SKIP_LOGIN	           = False
FRIENDLY_NAME              = 'My Satellite'
MAIL_FROM                  = FRIENDLY_NAME + ' - Pi.Alert Satellite <' + SMTP_USER + '>'
MAIL_TO                    = 'destination@example.com'
COLLECT_REPORTS_FOR_MAIL   = 12
# Since a scan is performed every 5 minutes, 12 corresponds to a period of 1 hour during which no successful transmission takes place until a notification is sent.

```

[Gmail Support Document](https://support.google.com/accounts/answer/185833?p=InvalidSecondFactor)

[iCloud Support Document](https://support.apple.com/en-us/102654)

[Outlook Support Document](https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944)


[Back](https://github.com/leiweibau/Pi.Alert-Satellite)