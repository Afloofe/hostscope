# Nothing changes on its own

HEMOSTAT never removes a file, changes the network or rewrites a configuration by itself. Every change is a person's decision, made in front of the cost.

- The response verbs (remediate, exec-block, account, kmod --unload, network) are dry runs by default: they print the plan, exit 5, and change nothing. --arm applies.
- In the console the confirmation is the arm: f opens the question, y answers it.
- On the Verbs tab the same order holds: the dry run's plan, then [a Arm], then the APPLY? question, then the armed run, through the same code the CLI runs. Account changes are made only this way or at the CLI, never by a rule.
- Every armed action goes through the Response Broker. It checks the build carries the module, the profile ($HEMOSTAT_PROFILE, it or ot), the signed engagement policy in $HEMOSTAT_POLICY if one is supplied, and the ticket in $HEMOSTAT_TICKET if one is presented (mint one with `hemostat ticket`). With no ticket the action still runs and says the authorization stage was not performed; a ticket that was presented and does not verify refuses the action.
- The authentication surface (ssh, your own session, anything declared in /etc/hemostat/critical) is never removed automatically.
- Every applied remedy writes an undo journal under /var/lib/hemostat/quarantine before it reports success, and a file it removes is moved into that vault rather than deleted. `hemostat undo <JOURNAL>` reverses it; the journal path is printed when the change applies.
- Nothing in the collector queue reaches a host. Triage is a record in the collector's ledger, and that is all.
