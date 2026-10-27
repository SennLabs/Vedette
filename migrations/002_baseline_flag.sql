-- Databases written before the baseline existed have already alerted on their history.
-- Mark them complete so the next sync is live rather than a silent catch-up.
UPDATE sync_state
   SET extra = 'baseline_complete'
 WHERE source = 'nvd' AND last_success IS NOT NULL;
