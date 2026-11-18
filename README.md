# PentAIWatch

PentAIWatch reads network logs (Zeek `conn.log`, Palo Alto traffic and threat logs) and flags
outside addresses whose behaviour towards your internal hosts looks like an agentic, AI-driven
penetration-testing tool: a sweep of many hosts or ports, a return to only the services that
answered, and short bursts of activity separated by pauses while a model decides what to do next.

It is under construction. The first working version arrives through pull requests.

Parts of the log parsing and session storage are taken from
[VulnScope MAX](https://github.com/bayanilla/vulnscope_max).

## License

MIT. See [LICENSE](LICENSE).
