FreePBX Agent UI (FOP2‑lite)

A lightweight agent UI for FreePBX: queue login/logout/pause per queue, live calls in queue, SLA dashboard with custom per‑queue rules, and agent “today” stats (inbound/outbound/ATT/available time). Works with FreePBX 15, Asterisk AMI, and MariaDB (CDR + Q‑Xact tables).

One‑liner install (Debian/Ubuntu/RHEL)
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SDenbow/freepbx-agent-ui/main/install_freepbx_agent_ui.sh)"

Or:

wget -O install_freepbx_agent_ui.sh https://raw.githubusercontent.com/SDenbow/freepbx-agent-ui/main/install_freepbx_agent_ui.sh \
  && sudo bash install_freepbx_agent_ui.sh
What you’ll need during install

FreePBX AMI host/port/user/pass

FreePBX MySQL host/port/db/user/pass (read‑only)

Member interface template (PJSIP/{ext} or SIP/{ext} or Local/{ext}@from-queue/n)

Queues and SLA rules (threshold & abandon‑exempt seconds)

Optional: Nginx hostname/port

Asterisk: add an AMI user

/etc/asterisk/manager.conf:

[ui_agent_app]
secret = STRONG_SECRET
read = system,call,log,verbose,command,agent,user,originate
write = system,call,agent,command,originate
permit = 10.0.0.0/255.255.255.0
writetimeout = 1000

Reload: asterisk -rx 'manager reload'

MySQL: create read‑only user
CREATE USER 'report_ro'@'%' IDENTIFIED BY 'report_ro_pw';
GRANT SELECT ON asteriskcdrdb.* TO 'report_ro'@'%';
FLUSH PRIVILEGES;

(Tighten host to the app IP if possible.)

Service management
systemctl status freepbx-agent-ui
journalctl -u freepbx-agent-ui -f
systemctl restart freepbx-agent-ui
Config files to tweak later

server/.env (ports, hosts, creds, TZ)

server/src/config.js (member interface template, per‑queue SLA rules)

server/src/sla.js & server/src/agentStats.js (adjust SQL to your Q‑Xact schema if needed)

Security tips

Restrict AMI user by IP; minimum privileges

Use HTTPS on Nginx; set a non‑default hostname

Consider integrating FreePBX User Management/LDAP in place of the MVP login (see server/src/auth.js)

🧪 Quick sanity test after install

systemctl status freepbx-agent-ui → running

Nginx URL loads UI (or serve the built /web/dist yourself)

Login with an extension (MVP auth) → see allowed queues

Press Login/Logout/Pause and verify in Asterisk CLI: asterisk -rvvvvv → queue show <queue>

Place a test call → Calls waiting updates

Check Today stats and SLA tiles (set time window to today).

🚀 Next steps

Swap MVP auth for actual UserMan/LDAP validation

Replace static queue ACL with DB‑backed mapping (or pull from FreePBX tables)

Add business‑hours logic or DID filters into the SLA query if desired
