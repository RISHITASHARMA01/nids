# Stackfusion SOP
**Last Updated:** 2026-06-02

---

## 1. Add a New Device to Cloudflare Zero Trust

**1. Get serial number**
- Windows: `wmic bios get serialnumber`
- Mac: `system_profiler SPHardwareDataType | grep Serial`
- Linux: `sudo dmidecode -s system-serial-number`
- iOS/Android: Settings → About → Serial Number

**2. Create posture rule**
```bash
curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/6a2a7ce805eed03fc70f7748334eb267/devices/posture" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"name":"Serial-<OS>-<SERIAL>","type":"serial_number","input":{"id":"<SERIAL>"}}'
```
Copy the `id` from the response.

**3. Add to all policies** — run the script in `SOP_add_device.py` with the posture rule ID.

**4. Verify** — on the device with WARP on, open any protected URL (e.g. `uat.fastag.ai/dashboard/`).

---

## 2. Fix apt Update Failing with WARP On

**Quick fix (temporary):**
```bash
warp-cli disconnect
sudo apt update && sudo apt install <package>
warp-cli connect
```

**Permanent fix:**
Go to Cloudflare Zero Trust → Settings → WARP Client → Device settings → Split Tunnels → Add these domains:
```
archive.ubuntu.com
security.ubuntu.com
```

---

## 3. Monitor Network Traffic

```bash
sudo iftop -i wlp0s20f3      # live traffic by connection
sudo nethogs wlp0s20f3       # traffic per app/process
bmon                          # bandwidth graphs
```

**Compare WARP vs no WARP latency:**
```bash
warp-cli connect && traceroute 1.1.1.1
warp-cli disconnect && traceroute 1.1.1.1
```

---

## 4. ZeroTier SSH

```bash
# Install
curl -s https://install.zerotier.com | sudo bash

# Join network
sudo zerotier-cli join <NETWORK_ID>
# Approve device at my.zerotier.com → Members

# SSH into device (IP only, no /16)
ssh username@<zerotier-ip>
```

---

## Protected URLs

| URL | Status |
|-----|--------|
| uat.fastag.ai/dashboard/ | Protected |
| s3.fastag.ai/dashboard | Protected |
| qa-sitepass.parkzap.com/…/admin | Protected |
| d-sitepass.parkzap.com/…/admin | Protected |
| live23.parkzap.com/…/admin | Protected |
| swift.fastag.ai/dashboard/ | Unprotected (bank IP issue) |
| testing.parkzap.com/…/admin | Unprotected (needs Tunnel) |
