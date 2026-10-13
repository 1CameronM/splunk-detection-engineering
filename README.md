# Splunk Detection Engineering Lab

This project is about writing detections instead of just collecting logs. I picked three common attacks, ran each one in my Active Directory lab, and wrote a Splunk search that catches it. Each detection is matched to MITRE ATT&CK.

The lab itself (the domain controller, Splunk, and Sysmon) comes from my other repo, [HomeLab](https://github.com/1CameronM/HomeLab). This repo is just the detection work I built on top of it.

## What I used

* Splunk Enterprise 10.4.2 on my Windows 11 laptop
* DC01 (Windows Server 2022, corp.local) with the Splunk Universal Forwarder
* Sysmon with the SwiftOnSecurity config on DC01
* Security, System, and Application logs from DC01

## Getting DC01 logs into Splunk

Before any of this worked I had to fix something I skipped in my original lab setup. DC01 was not sending any logs to Splunk. The port and firewall on my laptop were already set up, and the outputs.conf on DC01 already pointed at my laptop. The problem was that DC01 had no inputs.conf, so the forwarder had nothing to send. I made one for the Security, System, and Application logs, restarted the forwarder, and DC01 finally showed up.

![DC01 logs in Splunk](screenshots/forwarding-working.png)

## Detection 1: Brute force logins

**MITRE ATT&CK:** T1110 (Brute Force)

**The attack:** I tried to log in as jsmith with the wrong password 12 times in a row. Windows logs every failed login as Event ID 4625.

**The detection:**

```
index=* host=DC01 source="WinEventLog:Security" EventCode=4625
| eval target_user=mvindex(Account_Name,-1)
| stats count as failures, values(Source_Network_Address) as source_ips, min(_time) as first_seen, max(_time) as last_seen by target_user
| where failures >= 5
| convert ctime(first_seen) ctime(last_seen)
```

**How it works:** Every 4625 event has two Account_Name values. The first one is whoever made the request and the second one is the account being logged into, so I used mvindex to grab the second one. Then it counts the failures for each account and only shows accounts with 5 or more.

**Result:** jsmith showed up with 12 failures, all within about a second of each other. The source IP was ::1 because I ran the attack from DC01 itself.

![Brute force detection](screenshots/detection1-bruteforce.png)

## Detection 2: Encoded PowerShell

**MITRE ATT&CK:** T1059.001 (PowerShell) and T1027 (Obfuscated Files or Information)

**The attack:** Attackers like to hide what their PowerShell is doing by encoding it in Base64 and running it in a hidden window. I ran a harmless command (it only prints some text) that way three times, using the hidden window and execution policy bypass flags.

**The detection:**

```
index=* host=DC01 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 powershell
| rex "\bCommandLine[=:]\s*(?<cmd>[^\r\n]+)"
| rex "\bParentImage[=:]\s*(?<parent>[^\r\n]+)"
| where match(cmd, "(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}")
| table _time parent cmd
```

**How it works:** Sysmon Event ID 1 logs every process that starts, including the full command line. The search looks for PowerShell launches where the command line has an encode flag followed by a long Base64 string. PowerShell lets you shorten that flag (like `-enc` or `-e`), so the regex covers the short versions too.

**Result:** All three runs showed up. The parent process was powershell.exe since I started it from a PowerShell window. In a real attack it would probably be something sketchier, like Word or a script.

![PowerShell detection](screenshots/detection2-powershell.png)

## Detection 3: New account added to Domain Admins

**MITRE ATT&CK:** T1136.001 (Create Account) and T1098 (Account Manipulation)

**The attack:** I created a fake backdoor account called svc.backup and added it to Domain Admins. This is a common way for attackers to keep their access.

**The detection:**

```
index=* host=DC01 source="WinEventLog:Security" (EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| eval actor=mvindex(Account_Name,0)
| eval target=if(EventCode=4720, mvindex(Account_Name,-1), replace(mvindex(Account_Name,-1), "^CN=([^,]+),.*$", "\1"))
| eval created=if(EventCode=4720,1,0)
| eval priv_add=if(EventCode!=4720, if(match(Group_Name,"(?i)^(Domain Admins|Enterprise Admins|Schema Admins|Administrators)$"),1,0), 0)
| stats max(created) as account_created, max(priv_add) as added_to_priv_group, values(Group_Name) as group, values(actor) as performed_by, min(_time) as first_seen, max(_time) as last_seen by target
| where account_created=1 AND added_to_priv_group=1
| convert ctime(first_seen) ctime(last_seen)
```

**How it works:** Event 4720 means an account was created, and 4728, 4732, and 4756 mean an account was added to a group. Those happen all the time on their own, so the search only fires when the same account was created and also added to a privileged group. For the group events the account name shows up as a long CN= path, so I used a regex to pull out just the name.

**Result:** One row for svc.backup, added to Domain Admins by Administrator about a second after it was created. I deleted the account after testing.

![New admin detection](screenshots/detection3-newadmin.png)

## Problems I ran into

* **No inputs.conf on DC01.** Logs were not reaching Splunk at all. I fixed it by creating the file and restarting the forwarder.
* **My Splunk trial license expired.** Searches kept failing with a license error. Switching to the Free license fixed it, but Free does not allow alerts, so I ran each detection by hand against the simulated attack.
* **DC01 was on the wrong time zone.** It was set to Pacific, so its events showed up in Splunk 3 hours in the past and my searches came back empty. Changing it to Eastern fixed that.
* **My first brute force attempt barely logged.** Running net use against DC01 from DC01 only made 1 failed login event. Using Start-Process with a wrong password gave me all 12.
* **Sysmon was not on DC01.** It was only on my laptop, so I installed it on DC01 and added the Sysmon log to inputs.conf.

## What I learned

* A detection is only as good as the logs feeding it, and a big part of this project was just making sure the right logs were actually showing up.
* Some Windows events have fields that repeat, like two account names in one event, so you have to look at a real event before trusting a search.
* Matching two events together (created and added to a group) is more useful than alerting on either one alone.

## Limitations

* The thresholds are tuned for my lab. A regular user mistyping their password a few times could trigger Detection 1, and some real admin tools use encoded PowerShell, so Detection 2 would need an allowlist.
* All the attacks came from DC01 itself, so the source IP is not realistic.
* These run manually and not as scheduled alerts because I am on the Free license.

## What's next

* Run the brute force from my Kali VM so there is a real source IP
* Get alerting working with a developer license or a fresh trial
* Add a pass the hash detection
