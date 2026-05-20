// Paste this into the web app's DevTools console (member.royaltypro.app/app)
// to test the Fast Import Helper mockup end-to-end.
//
// Prereqs:
//   - The helper mockup is running: `cargo run --release` in
//     /Users/developer/Documents/PROJECTS/01_CSV_APP_helper_mockup/
//   - You're signed into the web app (any logged-in session)
//
// This snippet:
//   1. Probes the helper (GET /healthz)
//   2. Asks for absolute file path(s) via a prompt
//   3. POSTs them to /process
//   4. Polls /status/{id} until done
//   5. Reads the bundle bytes via fetch (file://) and triggers the existing
//      Data Transfer → Restore flow on them
//
// NOTE: file:// fetches are blocked by browsers from https origins.
// For the mockup, we'll just log the bundle path + password and let you
// manually use Data Transfer → Restore from File to pick it up.
// For the real product, the helper itself will provide the file picker
// via native OS dialog and the web app won't need absolute paths.

(async function rpFastImportMockup() {
  console.log('%c[rp-mock] Probing helper at http://127.0.0.1:17891', 'color: cyan; font-weight: bold');

  let health;
  try {
    const r = await fetch('http://127.0.0.1:17891/healthz');
    health = await r.json();
    console.log('%c[rp-mock] Helper alive:', 'color: green', health);
  } catch (e) {
    console.error('[rp-mock] Helper not reachable — is it running?\n' +
      'Start with: cd /Users/developer/Documents/PROJECTS/01_CSV_APP_helper_mockup && cargo run --release');
    return;
  }

  if (!health.native_tool_exists) {
    console.error('[rp-mock] Helper says native_tool binary is missing — build it first:\n' +
      'cd /Users/developer/Documents/PROJECTS/01_CSV_APP_native_tool && cargo build --release');
    return;
  }

  const defaultPath = '/Users/developer/Documents/prs_temp/test_data/BIGTEST_FILES/BIGTEST_1file_approx_284K_rows.csv';
  const pathsInput = prompt(
    'Enter absolute path(s) to CSV file(s), separated by commas:',
    defaultPath
  );
  if (!pathsInput) {
    console.log('[rp-mock] cancelled');
    return;
  }
  const paths = pathsInput.split(',').map(s => s.trim()).filter(Boolean);
  console.log('%c[rp-mock] Starting job for ' + paths.length + ' file(s)', 'color: cyan; font-weight: bold');

  const startResp = await fetch('http://127.0.0.1:17891/process', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ paths }),
  });
  if (!startResp.ok) {
    const err = await startResp.text();
    console.error('[rp-mock] /process failed:', startResp.status, err);
    return;
  }
  const { jobId } = await startResp.json();
  console.log('%c[rp-mock] Job started: ' + jobId, 'color: cyan');

  // Poll
  const t0 = Date.now();
  let status;
  for (let i = 0; i < 600; i++) { // up to 10 min
    await new Promise(r => setTimeout(r, 500));
    const r = await fetch('http://127.0.0.1:17891/status/' + jobId);
    status = await r.json();
    const dots = '.'.repeat((i % 4) + 1);
    console.log('%c[rp-mock] ' + status.state + dots + ' ' + ((Date.now() - t0) / 1000).toFixed(1) + 's', 'color: gray');
    if (status.state !== 'running') break;
  }

  if (status.state === 'done') {
    console.log('%c[rp-mock] ✓ DONE in ' + ((Date.now() - t0) / 1000).toFixed(1) + 's', 'color: lime; font-weight: bold; font-size: 14px');
    console.log('%c  bundle: ' + status.bundle_path, 'color: lime');
    console.log('%c  password: ' + status.password, 'color: lime');
    console.log('');
    console.log('%cNext step (mockup): manually open Data Transfer → Restore from File,', 'color: yellow');
    console.log('%cpick the bundle file, paste the password above.', 'color: yellow');
    console.log('');
    console.log('In the real product, the helper itself will provide the file picker');
    console.log('via native OS dialog and trigger the import automatically.');
  } else {
    console.error('[rp-mock] ✗ FAILED', status);
  }
})();
