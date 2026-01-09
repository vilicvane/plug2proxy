# TPROXY Testing with Multipass

This guide sets up an isolated VM for testing TPROXY functionality.

## Step 1: Install Multipass on Windows

Open PowerShell as Administrator:

```powershell
# Option A: Via winget
winget install Canonical.Multipass

# Option B: Download installer from https://multipass.run/download/windows
```

Restart your terminal after installation.

## Step 2: Create a Test VM

In PowerShell (not WSL2):

```powershell
# Create VM with 2 CPUs, 2GB RAM
multipass launch -n tproxy-test -c 2 -m 2G -d 10G 22.04

# Check it's running
multipass list
```

## Step 3: Build the Binary in WSL2

In WSL2:

```bash
cd /home/vilicvane/projects/vilicvane/plug2proxy-v2

# Build release binary with cross (for GLIBC compatibility)
cross build --release --target x86_64-unknown-linux-gnu

# Build test binary
cross build --release --target x86_64-unknown-linux-gnu --bin tproxy_test

# Note the paths:
# - target/x86_64-unknown-linux-gnu/release/plug2proxy
# - target/x86_64-unknown-linux-gnu/release/tproxy_test
```

## Step 4: Copy Binaries to VM

In PowerShell, the WSL2 filesystem is accessible at `\\wsl$\`:

```powershell
# Find your WSL distro name
wsl -l -v

# Copy binaries (adjust distro name if needed)
multipass transfer "\\wsl$\Ubuntu\home\vilicvane\projects\vilicvane\plug2proxy-v2\target\x86_64-unknown-linux-gnu\release\tproxy_test" tproxy-test:/home/ubuntu/
multipass transfer "\\wsl$\Ubuntu\home\vilicvane\projects\vilicvane\plug2proxy-v2\target\x86_64-unknown-linux-gnu\release\plug2proxy" tproxy-test:/home/ubuntu/

# Copy the setup script
multipass transfer "\\wsl$\Ubuntu\home\vilicvane\projects\vilicvane\plug2proxy-v2\res\in\tproxy_vm_setup.sh" tproxy-test:/home/ubuntu/
```

## Step 5: Setup TPROXY in VM

```powershell
# Shell into the VM
multipass shell tproxy-test
```

Inside the VM:

```bash
# Make scripts executable
chmod +x tproxy_vm_setup.sh tproxy_test plug2proxy

# Run setup (configures nftables and routing)
sudo ./tproxy_vm_setup.sh setup

# Run the TPROXY test
sudo ./tproxy_test
```

## Step 6: Test TPROXY

In another PowerShell window:

```powershell
multipass exec tproxy-test -- curl -v --connect-timeout 5 http://example.com/
```

The TPROXY listener should intercept this and show the original destination.

## Cleanup

```powershell
# Stop the VM
multipass stop tproxy-test

# Delete completely
multipass delete tproxy-test
multipass purge
```

## Recovery if Network Breaks

If you misconfigure and can't SSH:

```powershell
# Force restart
multipass restart tproxy-test

# Or delete and recreate
multipass delete tproxy-test --purge
multipass launch -n tproxy-test -c 2 -m 2G -d 10G 22.04
```

## Notes

- The VM has its own completely isolated network stack
- Breaking the VM's network doesn't affect your host or WSL2
- You can always delete and recreate the VM in seconds
