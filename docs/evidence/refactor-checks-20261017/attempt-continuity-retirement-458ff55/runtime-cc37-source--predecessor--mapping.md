# Original-to-boundary mapping

Original TestAttemptRejectsRetiredContinuityPhase is retained unchanged in cloud_test.go:217-222. Its helper smallAttempt uses canonical ULID 0000000000F9PR1WNVDTEXS31Z and prefix bootstrap/a; the new public-entry test retains both. Optional tools is omitted; New treats absent tools as an empty object, exactly like the original empty tools object.

- Original nonnil Phase("continuity") error -> real public Run invokes New then the same production dispatcher and must return exit code 1.
- Original unknown-attempt-phase substring -> complete diagnostics must equal unknown attempt phase "continuity" followed by exactly one newline.
- Actual temp JSON config is marshaled with encoding/json/v2 and written mode0600; production New creates its work directory. External package attempt_test accesses no internals, fake Cloud/Runner/Sleep, or network stub.

Only one new file is added. All original tracked paths, helpers, modules and production are unchanged from exact parent09fbf0bb; the original file/declaration also match the frozen bfca6036 inventory hashes. No original deletion/retirement or runtime qualification is claimed. This is the expressly accepted local manager/CLI boundary; broader CLI dispatch, OCI, cloud, race and performance behavior are outside scope.
