# Electric Cars – Ride Auditor

`car_audit.py` is an offline tool (no internet, no cloud) that turns a FAT32 USB
stick into a tamper-evidence logger for kids' rental cars, and audits it on your
laptop to estimate rides, yank/tamper events and revenue.

## Run it on Windows

1. Install Python from python.org (tick **"Add python.exe to PATH"**).
2. Put `car_audit.py` in a folder, e.g. `C:\CarAudit`.
3. Open **Command Prompt as administrator** (needed for raw USB reads), then:

   ```
   cd C:\CarAudit
   python car_audit.py
   ```

4. Menu: `1` initialize a stick, `2` audit, `3` change price/ride length,
   `4` ledger history, `5` raw drive inspection, `6` about/limitations.

Reports are saved to `C:\Users\<you>\car_audit_reports\` (open the `.html`).

## Important

- The USB stick must be formatted **FAT32**.
- Always **Safely Remove / Eject** after initializing or auditing.
- If Windows offers to "Scan and fix" the stick, choose **Continue without
  scanning** – a repair erases the yank evidence.
- Run the **calibration test** once per car (drive N rides, audit, enter N).
  Some MP3 boards never write to the stick; then rides cannot be counted from
  the stick alone and only tamper detection works. See menu option 6.
