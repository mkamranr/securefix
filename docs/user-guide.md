# User guide

## 1. Sign in
Sign in with a **Windows (Active Directory)** account once an administrator has set up Windows sign-in, or with a
**local account** an administrator created. The first account created on a fresh install becomes the administrator.
There is no self-registration after that.

Windows users get a profile on their first sign-in. Their password stays in Active Directory, so it can't be
changed or reset in the app. They can sign in as `jdoe`, `CORP\jdoe` or `jdoe@corp.example.com`.

## 2. Connect GitLab (Settings)
Save a GitLab token: a personal, project or group access token, or an OAuth token. It is checked against GitLab,
then stored encrypted, and it is never shown again.

| Token scopes | Lets you |
| --- | --- |
| `read_api` + `read_repository` | analyze commits |
| `api` | also post analyses to issues, open fix merge requests and dismiss findings |

You need at least the **Developer** role on a project to see its vulnerabilities. Creating an issue needs
**Reporter**, and linking an issue to a vulnerability needs **Developer**.

## 3. Analyze a commit
On **Analyze Commit**, pick a project, a branch and a commit. Each commit shows whether its SAST scan has finished,
how many findings it has, and whether it was already analyzed. Only scanned commits can be analyzed.

Choose the **severities to analyze**. Critical and High are checked by default. Findings of other severities are
listed as skipped and don't use the model. The browser remembers your choice.

Choose whether the model **thinks** before it answers. With thinking **on** (the default an administrator sets), a
reasoning model such as Qwen3 works through the code step by step first: this is slower and generates more tokens,
but is often more careful. With thinking **off** it answers directly and faster. The browser remembers this choice too.

**Start Analysis** queues the job. The page follows its progress live, and you can **Cancel** it.

## 4. Review the results
The list shows each finding's severity, verdict, **confidence**, location, the **time** its analysis took ("Copied"
when it was copied from an earlier scan without asking the model) and its GitLab issue. The header shows whether
the model was thinking, and the summary shows the average time per analyzed finding.

Expanded, every finding shows:

- **Verdict**: *Real*, *False positive* or *Needs review* (the independent runs disagreed);
- **Confidence**, the verdict of each independent run, the analysis time and the tokens the model generated;
- **Reasoning** and **evidence** (source, sink, mitigations);
- the **proposed fix** as a diff, with its validation output (build, tests, re-scan);
- **the code the model saw**: every excerpt and why it was included;
- a warning if the code contains text addressed to an AI or reviewer (treat that verdict with suspicion);
- a *Copied* tag, with a link, when the analysis was copied from an earlier scan.

## 5. Take action
| Action | Notes |
| --- | --- |
| **Post analysis to GitLab issue** | Comments on the finding's issue: the one linked to its vulnerability record, or one this app created earlier. If there is none, a confidential issue is created first (severity, location, scanner details), assigned to you and linked to the vulnerability. Each analysis is posted once; afterwards the button is disabled and the page links to the comment. A copied analysis counts as posted when the one it was copied from was posted. |
| **Post several at once** | Tick analyzed findings in the list (or the header box for all of them) and choose *Post N to GitLab issues*. Already-posted analyses can't be selected. |
| **Open fix merge request** | New branch from the analyzed commit, one commit with the fix, MR into the analyzed branch. |
| **Dismiss as false positive** | Only for findings with a vulnerability record (default branch). Never automatic. |
| **Open vulnerability in GitLab** | Opens the vulnerability page, or the pipeline's security report on branches without a record yet. |
| **Retry failed** | Analyzes only the findings that failed (e.g. the model was unreachable), in the same analysis. |
| **Run again** | Starts a new analysis of the same commit with the same thinking setting and the current *Code per finding* budget. Unchanged findings are copied; a new result from the model can be posted to the same issue. |
| **Run with thinking off / on** | Starts a new analysis of the same commit with the other thinking setting. Results are only copied between analyses with the same setting, so the model really answers again. |

Every action is recorded on the finding with who did it and when.

### Comparing thinking on and off
Open an analysis and choose **Run with thinking off** (or **on**). Then compare the two analyses: the verdicts and
confidence in the list, the *avg time per finding* tile, and the time and tokens of each finding. **History** shows
each analysis's thinking setting, and the Excel report has *Model thinking* and *Analysis time* on the Summary sheet and
*Analysis time (s)* and *Tokens generated* per finding.

To compare **code budgets**, an administrator changes *Code per finding* on the Admin page and then chooses
**Run again**: the new analysis uses the new budget and asks the model again. Findings whose code already fit the
old budget get exactly the same prompt, so their earlier result is reused. The header, History and the Excel
report show each analysis's budget.

The time is wall-clock time for the whole finding: every triage run, waiting for a free slot on vLLM, and the fix with
its validation. Compare analyses run while vLLM was similarly busy.

## 6. Shared analyses
**History** has three tabs:

- **Mine**: analyses you started.
- **Shared with me**: analyses other people ran on projects where you are **Developer or higher** in GitLab. That
  is the same role GitLab requires to see a project's vulnerabilities. Your role is checked with your own GitLab
  token, so you need to have saved one.
- **Everyone** (administrators only): every analysis in the app.

Someone else's analysis opens **read-only**. You can see every result and download the Excel report, but you can't
post analyses, open fix merge requests, dismiss findings, or cancel or retry the analysis. Only the person who started
an analysis can do that, and that applies to administrators too. To act on findings yourself, choose **Run again**:
it starts your own analysis of the same commit. Unchanged findings are copied, and analyses already posted stay
marked as posted, so nothing is posted twice.

## 7. Excel report
**Download report (Excel)** is on the analysis page and on each row of the **History** page. The workbook has:

- a **Summary** sheet: project, branch, commit, who ran it, totals per verdict and a severity × verdict table;
- a **Findings** sheet with one row per finding: severity, verdict, confidence, CWE, location (linked to the file at
  the analyzed commit), GitLab issue, vulnerability link, whether it was posted (by whom and when), the proposed fix
  and its validation, fix MR, dismissal, *copied from*, scanner, status, reasoning and errors.

Columns are filterable and colour-coded. A running analysis downloads its current state.
