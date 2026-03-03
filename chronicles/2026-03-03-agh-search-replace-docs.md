timestamp: 2026-03-03T02:30:00+01:00
participants: [assistant]

summary:
- Ran tools/agh_search_replace.py to update documentation mentions of the legacy debug_pdb_path to reference the new structured field: debug_metadata.pdb.path (legacy debug_pdb_path kept).
- Changes applied to: doc/decoder-parity-checklist.md
- Produced a patch file: docs-debug_pdb_rewrite.patch and a backup decoder-parity-checklist.md.agh.bak

commands run:
- python3 tools/agh_search_replace.py --path doc --pattern "\\bdebug_pdb_path\\b" \
  --replace "debug_metadata.pdb.path (legacy debug_pdb_path kept)" --apply --patch-file docs-debug_pdb_rewrite.patch --force

files modified:
- doc/decoder-parity-checklist.md (in-place)
- docs-debug_pdb_rewrite.patch (patch file)
- doc/decoder-parity-checklist.md.agh.bak (backup)

notes:
- Only documentation under doc/ was updated; source code was not modified by this run.
- The replacement is intentionally conservative: the docs now point readers to debug_metadata.pdb.path while noting the legacy debug_pdb_path alias remains for compatibility.
- This run used --force due to an uncommitted working tree; a patch file was produced for review.

next steps:
- Review docs-debug_pdb_rewrite.patch and commit when ready.
- Consider running the tool again after finalizing other field names (if any) to update additional docs.

end
