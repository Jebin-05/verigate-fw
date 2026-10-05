Ablation, not a production configuration: `latency_stage2` (LLM off) run with
`ServiceState.trusted_firmware` temporarily returning `(None, False)`, i.e. Stage-1 check #9 never
has a reference image. Same machine and session as `latency_stage2/2026-10-02_1626_3300b9f`
(check #9 on), so the two medians are an A/B of the check's cost. The temporary edit was reverted
before any other run.
