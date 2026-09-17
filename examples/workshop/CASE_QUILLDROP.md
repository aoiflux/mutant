# Case QUILLDROP — the story the workshop is built on

> This is the narrative spine for the hands-on tools in `07_`–`12_`. Read it out
> loud at the start. Everything the students build answers one of its questions.

## The brief (read this to the room)

**Meridian Logistics**, 400 people, moves freight. On **12 March 2026** their
finance team could not open the quarterly close. Files were there; contents were
garbage. Somebody had been inside for a day and a half before that.

You are handed one thing: a **triage collection** from the first machine that
misbehaved — `MRD-FIN-07`, the workstation of an accounts-payable clerk. No
memory capture. No packet capture. Nobody took a disk image; the machine was
rebuilt before anyone thought to.

What you have is a folder of files and a `bodyfile` — the four timestamps of
every file at the moment of collection.

That is the real situation. Most incidents are like this. The exciting part is
not that you have great evidence; it is that **the attacker left contradictions
in the evidence they controlled**, and contradictions are machine-findable.

## What actually happened (facilitator's copy — do NOT read this out)

| # | Time (UTC) | Event | Artifact it lands in |
|---|---|---|---|
| 1 | 11 Mar 09:14 | Clerk opens an "unpaid invoice" email | `.eml` in the Outlook export |
| 2 | 11 Mar 09:16 | Clicks the link; browser saves `Invoice_MRD-88412.pdf.exe` | file + **Mark-of-the-Web** ADS carrying the origin URL |
| 3 | 11 Mar 09:17 | Dropper runs, writes `svchost.exe` into `%AppData%\Roaming\MeridianSync\` | a PE where no PE belongs |
| 4 | 11 Mar 09:17 | Persistence: Startup `.cmd` + an exported `Run` key | startup folder, `.reg` file |
| 5 | 11 Mar 09:22 → 12 Mar | Implant beacons every **300 s** to one host | the agent's own `.log` |
| 6 | 11 Mar 22:40 | Finance + HR documents copied to a hidden staging dir | staging tree |
| 7 | 11 Mar 23:05 | Staged files zipped into `bkp_20260311.zip` | **archive = the attacker's own inventory list** |
| 8 | 12 Mar 00:10 | **Timestomp** — implant files backdated to look two years old | `mtime` earlier than `crtime` |
| 9 | 12 Mar 00:12 | Log truncated + rotated to cut out the beacon window | a hole in a sequence |
| 10 | 12 Mar 00:15 | Staging directory deleted | files gone, timestamps left behind |

## The five questions → the five tools

| Question | Tool | File |
|---|---|---|
| **How did it get in?** | Dropzone — *every download carries a receipt* | `07_dropzone.mut` |
| **What happened, in what order?** | Strata — one supertimeline, then Sigma over it | `08_supertimeline.mut` |
| **Where did they lie to me?** | Revenant — anti-forensics detection | `09_revenant.mut` |
| **What did they take?** | Quarry — exfil reconstruction from the archive | `10_quarry.mut` |
| **Will this survive a lawyer?** | Verdict — sealed, signed, reproducible case | `11_verdict.mut` |

Bonus, if the room is fast: **What *is* this thing?** → `12_imposter.mut`
(binary triage; recovers function names from a *stripped* Go binary).

## The three lines worth stealing

Use these as section headers. They land.

1. **"You cannot delete a fact. You can only create a contradiction."**
   Deleting a file does not remove it from the timeline — it adds an event.
   Backdating a timestamp does not make a file old — it makes it *impossible*.

2. **"The attacker wrote you an inventory list and called it a zip."**
   Exfil staging is the one step an attacker cannot do quietly, because it
   requires enumerating exactly what they wanted.

3. **"Analysis is what you did. Evidence is what you can prove you did."**
   The difference is one `case_open` and one signature.

## Why this case, and not "find the deleted file"

Deleted-file recovery is a *lookup*. It teaches a tool, not a method. This case
teaches the four moves that transfer to every investigation you will ever run:

- **Model** the artifact (what fields does this thing actually assert?)
- **Normalize** time (everything is a different epoch and they all lie differently)
- **Correlate** two sources that were never meant to be compared
- **Prove** the result is reproducible by someone who does not trust you

Malware is the vehicle because malware *has to act*, and acting leaves the
contradictions. A hoarder of illegal images leaves you a pile of files. An
intruder leaves you a **sequence**, and a sequence can be interrogated.

## Generating the evidence

Evidence is synthesized with [`fsagen`](https://github.com/aoiflux/fsagen),
seeded so **every student gets byte-identical evidence** and therefore
byte-identical findings. See `evidence/README.md`.

```
fsagen --seed 88412 --playbook examples/workshop/evidence/quilldrop.playbook.yaml \
       --timeline examples/workshop/evidence/case_quilldrop.body \
       examples/workshop/evidence/case_quilldrop
```

The determinism is not a convenience — it is the point of `11_verdict.mut`. Same
seed → same evidence → same report → **same SHA-256**. Two students on two
laptops produce the same digest, and that is what reproducible forensics means.
