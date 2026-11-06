# AEGIS for Mac: user guide

This guide is for people who were invited to try AEGIS on their Mac. It
covers the AEGIS menu-bar app, which arrived with AEGIS 0.1.0 build 39.
AEGIS is a test version: it has not been released, and it may still fail
in ways this guide does not describe. If something looks wrong, send the
diagnostics (see the end of this guide) to the person who invited you.

AEGIS sends all of your Mac's internet traffic through a relay run by the
person who invited you. Its **leak guard** makes sure that, while the
tunnel runs, apps cannot send traffic past it.

## What you need

- A Mac with Apple silicon (M1 or later) and macOS 14.4 or later. Intel
  Macs are not supported.
- An administrator account on that Mac (you need its password a few times
  during setup).
- Two things from the person who invited you, sent privately:
  - the AEGIS app, as a file named like `AEGIS-39-….zip`;
  - your **invitation folder**: a folder (usually also zipped) that
    contains exactly two folders, `bundle` and `identity`. It holds your
    private key: do not share it, and do not open or change anything in it.

The invitation folder must already be prepared for your Mac by the person
who invited you. AEGIS cannot yet turn a bare invitation code into this
folder by itself.

## Install

1. Double-click the AEGIS zip file. It unpacks to **AEGIS**.
2. Drag **AEGIS** into the **Applications** folder. AEGIS works only from
   there.
3. If you received the invitation folder as a zip file, double-click it
   to unpack it, and leave the folder where it is. Do not open it.
4. Open **AEGIS** from the Applications folder. macOS may ask whether you
   want to open an app downloaded from the internet; click **Open** (AEGIS
   is signed and checked by Apple).

AEGIS has no window and no Dock icon. It lives in the **menu bar** at the
top right of the screen, as a small shield. Click the shield to open the
AEGIS menu.

## Set up (first time only)

The first time you open AEGIS it shows **Welcome to AEGIS**. Click **Set Up
Now**. (If you click **Later**, choose **Set Up AEGIS…** or **Continue
Setup…** in the AEGIS menu whenever you are ready.)

Setup has four steps. Before each one AEGIS explains what macOS will ask;
click **Continue**, then answer the macOS dialog.

1. **Turn on the network extension.** macOS asks you to allow AEGIS in
   System Settings. AEGIS shows you where and can open System Settings for
   you.
   - macOS 15 or later: **System Settings > General > Login Items &
     Extensions**, then the ⓘ button next to **Network Extensions**, and
     switch **AEGIS** on.
   - macOS 14: **System Settings > Privacy & Security**, scroll down to
     **Security**, and click **Allow** next to the message about AEGIS.

   AEGIS waits up to two minutes for you. If it stops waiting before you
   are done, choose **Finish Setup After Approval…** in the AEGIS menu: it
   checks again, and continues once the switch is on.
2. **Turn on the leak guard.** macOS asks: *"AEGIS" would like to filter
   network content.* Click **Allow**.
3. **Import your invitation.** Click **Choose Folder…** and select your
   invitation folder (the one that contains `bundle` and `identity`), then
   click **Import**. AEGIS asks whether to remove the folder from this Mac
   after the import:
   - **Import and Keep Folder** (recommended until AEGIS has connected
     once): you can set AEGIS up again from it later.
   - **Import and Remove Folder**: AEGIS removes it after a successful
     import, once it has checked that nothing in it changed.

   macOS then asks for an **administrator's name and password** ("… is
   trying to change the AEGIS VPN device identity"). Enter them. If macOS
   asks whether AEGIS may access a folder such as Downloads, click **OK**.
   The zip file the folder came in holds your private key too: move it to
   the Trash once AEGIS has connected.
4. **Add the VPN configuration.** macOS asks: *"AEGIS" would like to Add
   VPN Configurations.* Click **Allow**, and enter your password or use
   Touch ID if asked. Answer within 30 seconds; if you miss it, choose
   **Continue Setup…** again.

When setup is complete, AEGIS says **AEGIS is set up**.

## Connect and disconnect

- Click the shield, then **Connect**. The title changes to **Connecting…**
  and, a few seconds later, to **Connected**. The shield becomes a closed
  lock.
- To stop, click the shield, then **Disconnect**.

AEGIS connects only while its leak guard is on. If the leak guard is off,
**Connect** turns it on first (macOS may ask you to **Allow** again).

## What the menu shows

The first line of the menu is the state. The lines below it say more about
the leak guard and the certificate (your access).

| State | What it means | What to do |
| --- | --- | --- |
| Checking… | AEGIS is reading the state (a few seconds after it opens). | Wait. |
| Move AEGIS to the Applications folder | AEGIS was opened from somewhere else, for example Downloads. | Quit AEGIS, drag it into Applications, open it from there. |
| Needs approval in System Settings | macOS waits for you to switch AEGIS on (setup step 1), or it was switched off. | Choose **Open System Settings…**, switch AEGIS on, then **Finish Setup After Approval…**. |
| Setup needed: turn on the network extension | Setup has not started. | Choose **Set Up AEGIS…**. |
| Setup needed: turn on the leak guard | The leak guard is off or was removed. | Choose **Continue Setup…** (or just **Connect**). |
| Setup needed: import your invitation | AEGIS has no identity yet. | Choose **Continue Setup…** or **Import Invitation…**. |
| Setup needed: add the VPN configuration | The VPN configuration is missing. | Choose **Continue Setup…** (or just **Connect**). |
| Update ready: finish installing it | You installed a newer AEGIS. | Choose **Finish Update…** (while disconnected). |
| Disconnected | Ready; the Mac uses its normal network. | **Connect** when you want the tunnel. |
| Connecting… | The tunnel is starting. Until it connects, macOS holds your traffic, so nothing leaves outside the tunnel. | Wait a few seconds. |
| Connected | All traffic goes through the AEGIS relay. Leak guard line: *on, guarding traffic*. | Nothing. |
| Disconnecting… | The tunnel is stopping. | Wait. If it lasts, **Force Stop Tunnel…** appears. |
| Blocked by leak guard (reconnecting) | The connection to the relay was lost and AEGIS is rebuilding it. Meanwhile your traffic is held: nothing leaks, but nothing works either. | Usually it recovers within seconds. If not, **Disconnect** (or **Force Stop Tunnel…**) to get your normal network back. |
| Blocked by leak guard (still connecting) | The tunnel has been starting for more than 45 seconds; your traffic is held. | **Disconnect** or **Force Stop Tunnel…**, check your internet connection, then **Connect** again. If it keeps happening, send the diagnostics. |
| Certificate expired: traffic blocked | Your access has expired while connected; traffic is held so nothing leaks. | **Disconnect** (or **Force Stop Tunnel…**), then ask for a new invitation and import it. |
| Certificate expired | Your access has expired, or the relay no longer accepts it. | Ask for a new invitation, then **Import Invitation…**. |
| Certificate renewing | AEGIS is renewing your access; it finishes when you connect. | **Connect**. |
| Network extension not responding | The AEGIS extension does not answer. | Restart the Mac. If that does not help, send the diagnostics. |

Detail lines:

- **Leak guard: on** — ready; **on, guarding traffic** — protecting the
  running tunnel; **off** — AEGIS turns it on before it connects; **on,
  but not running** — restart the Mac; if it stays, send the diagnostics.
- **Certificate: valid until …** — your access works until then and
  renews itself when you connect. If it says the renewal **waits for the
  next connect**, disconnect and connect again before the time it shows.
  If it says **expired** or **replaced**, you need a new invitation.
- **Last action: …** — why the last thing you chose did not work.

## Import a new invitation

When your access expires, the person who invited you sends a new
invitation folder. Disconnect first, then choose **Import Invitation…** and
follow step 3 of the setup.

If the import is refused, AEGIS says why. The most common reasons:

- *This folder holds an item AEGIS does not expect*: Finder sometimes adds
  a hidden file named `.DS_Store` when a folder is opened. In Finder, open
  the folder, press **Shift-Command-Period** to show hidden files, move
  `.DS_Store` to the Trash (also inside `bundle` and `identity`), press
  **Shift-Command-Period** again, and import again. Do not delete anything
  else.
- *This folder must be private to you*: in Finder select the folder,
  choose **File > Get Info**, and under **Sharing & Permissions** set every
  entry other than you to **No Access**; do the same for `bundle` and
  `identity` inside it.
- *No administrator approved the import*: the password dialog was
  cancelled or not answered in two minutes. Nothing changed; try again.

## Quit AEGIS

**Quit AEGIS** only closes the menu:

- If you are connected, AEGIS asks: **Quit and Stay Connected** keeps the
  tunnel and the leak guard running (open AEGIS again from Applications to
  disconnect later); **Disconnect and Quit** disconnects first.
- If the tunnel is still connecting or is blocked, **Disconnect and Quit**
  gives the Mac its normal network back; **Quit Anyway** leaves it holding
  your traffic.
- The leak guard is never turned off by quitting. AEGIS never turns it off
  at all.

## Send diagnostics

If something does not work, choose **Copy Diagnostics** and paste the
result into a message to the person who invited you. It contains the state,
error codes and times only: no keys, invitation, user name or full IP
address (addresses are cut to their first part, for example `203.x.x.x`).

## Update AEGIS

Quit AEGIS, replace AEGIS in the Applications folder with the new version,
and open it. The menu then shows **Update ready**; while disconnected,
choose **Finish Update…**.

## Remove AEGIS

There is no uninstall in the menu yet. Ask the person who invited you; they
have a tool that removes the VPN configuration, the leak guard, your
identity and the extension in the right order.

## For the person who sends invitations

The menu-bar app imports only a prepared invitation folder: the
`bundle/` and `identity/` tree that `aegis-ne-host --import` takes, with
an identity enrolled online (`identity/online-completed.json`). Prepare it
for the friend's device id with `aegis-client device prepare`,
`device bundle-inspect --identity-dir` and `device redeem`, as in
[enrollment from a bundle and an invitation](install-and-enable.md#enrollment-from-a-bundle-and-an-invitation),
in a new private (`0700`) folder; then zip it with
`ditto -c -k --keepParent <folder> <folder>.zip` (which keeps the private
modes) and send it privately. The device key is then generated on your
Mac, not on the friend's, until in-app enrollment exists; delete your copy
once the friend has connected. Send the stapled ZIP of the app build
alongside. The menu-bar app runs only the host's existing CLI verbs; the
full verb reference is in [install, enable and enroll](install-and-enable.md).

Parent: [macOS documentation](README.md).
