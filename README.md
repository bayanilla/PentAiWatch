# PentAIWatch

PentAIWatch reads network logs (Zeek `conn.log`, Palo Alto traffic and threat logs) and flags
outside addresses whose behaviour towards your internal hosts looks like an agentic, AI-driven
penetration-testing tool: a sweep of many hosts or ports, a return to only the services that
answered, and short bursts of activity separated by pauses while a model decides what to do next.

It is under construction. The first working version arrives through pull requests.

## Code taken from VulnScope MAX

The log reading and session storage come from
[VulnScope MAX](https://github.com/bayanilla/vulnscope_max) at commit `6a7ac93`, trimmed to what
this tool needs. When a parser or de-duplication fix lands in MAX, compare these files and carry
it over.

| Here | From MAX | What changed |
|---|---|---|
| `pentaiwatch/parsers/zeek.py` | `vulnflow/parsers/zeek.py` | Industrial-protocol handling removed. Each session keeps Zeek's raw `conn_state`, the packets sent back, and a note that its time is a start time. |
| `pentaiwatch/parsers/paloalto.py` | `vulnflow/parsers/paloalto.py` | Unchanged for now. |
| `pentaiwatch/parsers/_util.py` | `vulnflow/parsers/_util.py` | Unchanged. |
| `pentaiwatch/store.py` | `vulnflow/store.py` | Explorer queries and Zeek event storage removed. Three session columns added: `state`, `pkts_in`, `start_method`. De-duplication is the same SQL. |
| `pentaiwatch/load.py` | `vulnflow/normalize.py` | Nessus findings removed. Files that are not Zeek or Palo Alto logs are left out and listed. |
| `pentaiwatch/schema.py` | `vulnflow/schema.py` | Findings and industrial events removed. Sessions gain the three fields above. |
| `pentaiwatch/netmap.py`, `scanners.py` | same names | Reading of `network_map.csv` and `known_scanners.csv` only. |
| `pentaiwatch/resources.py`, `errors.py` | same names | Settings are named `PENTAIWATCH_...` instead of `VULNSCOPE_...`. |

## Development

    pip install -r requirements-dev.txt
    python -m unittest discover -s tests -t .
    ruff check . && mypy
    python scripts/check_repo.py

CI runs the same checks on every pull request.

## License

MIT. See [LICENSE](LICENSE).
