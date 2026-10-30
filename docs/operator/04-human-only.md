# Nothing changes on its own

HEMOSTAT never removes a file, changes the network or rewrites a configuration by itself. Every change is a person's decision, made in front of the cost.

- The response verbs (remediate, exec-block, account, kmod --unload, network; fw block, fw confirm and fw statekill on the firewall) are dry runs by default: they print the plan, exit 5, and change nothing. --arm applies.
- In the console the confirmation is the arm: f opens the question, y answers it.
- On the Verbs tab the same order holds: the dry run's plan, then [a Arm], then the APPLY? question, then the armed run, through the same code the CLI runs. Account changes are made only this way or at the CLI, never by a rule.
- Every armed action goes through the Response Broker. It checks the build carries the module, the profile ($HEMOSTAT_PROFILE, it or ot), the signed engagement policy in $HEMOSTAT_POLICY if one is supplied, and the ticket in $HEMOSTAT_TICKET if one is presented (mint one with `hemostat ticket`). With no ticket the action still runs and says the authorization stage was not performed; a ticket that was presented and does not verify refuses the action.
- The authentication surface (ssh, your own session, anything declared in /etc/hemostat/critical) is never removed automatically. A declared name without a unit suffix means NAME.service (php8.1-fpm is php8.1-fpm.service), and a declared or listening unit is protected under every name systemd knows it by (mysqld protects the mariadb.service it is an alias of).
- The white team's login and the DataDog agent's accounts (whiteteam, dd-agent, ddagentuser, datadog, in any case) are never changed, on any host and whatever is declared: no lock, no group drop, no session ended (nor another account's session one of them is running in), no sudoers line stripped, no process of theirs killed or suspended. Their findings keep their severity and show no fix, marked OUT OF SCOPE, human-only; if one must change, you change it by hand.
- Every applied remedy writes an undo journal under /var/lib/hemostat/quarantine before it reports success, and a file it removes is moved into that vault rather than deleted. `hemostat undo <JOURNAL>` reverses it; the journal path is printed when the change applies.
- Nothing in the collector queue reaches a host. Triage is a record in the collector's ledger, and that is all.
