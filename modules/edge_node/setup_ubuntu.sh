#!/bin/bash
set -e

# Ubuntu Base RootFS URL (ARM64)
UBUNTU_URL="http://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.4-base-arm64.tar.gz"
UBUNTU_TAR="ubuntu-base.tar.gz"
DEVICE_DIR="/data/local/ubuntu"

echo "[*] Downloading Ubuntu Base (arm64)..."
if [ ! -f "$UBUNTU_TAR" ]; then
    wget -qO $UBUNTU_TAR $UBUNTU_URL
fi

echo "[*] Preparing Android device for Ubuntu Chroot..."
adb shell 'su -c "mkdir -p '$DEVICE_DIR'"'

echo "[*] Pushing Ubuntu RootFS to device (this may take a minute)..."
adb push $UBUNTU_TAR /data/local/tmp/

echo "[*] Extracting RootFS on device..."
adb shell 'su -c "cd '$DEVICE_DIR' && tar -xf /data/local/tmp/'$UBUNTU_TAR' --numeric-owner"'

echo "[*] Setting up DNS..."
adb shell 'su -c "echo '\''nameserver 8.8.8.8'\'' > '$DEVICE_DIR'/etc/resolv.conf"'
adb shell 'su -c "echo '\''127.0.0.1 localhost'\'' > '$DEVICE_DIR'/etc/hosts"'

echo "[*] Creating chroot mount script..."
MOUNT_SCRIPT="/data/local/ubuntu_mount.sh"
cat << 'EOF' > mount_script.sh
#!/system/bin/sh
UBUNTU_DIR="/data/local/ubuntu"

# Mount necessary filesystems
mount -t proc proc $UBUNTU_DIR/proc
mount -t sysfs sysfs $UBUNTU_DIR/sys
mount -o bind /dev $UBUNTU_DIR/dev
mount -o bind /dev/pts $UBUNTU_DIR/dev/pts
mount -t tmpfs tmpfs $UBUNTU_DIR/dev/shm

# Enter chroot
echo "[+] Entering Ubuntu God Node..."
chroot $UBUNTU_DIR /bin/su - root
EOF

adb push mount_script.sh /data/local/tmp/
adb shell 'su -c "mv /data/local/tmp/mount_script.sh '$MOUNT_SCRIPT' && chmod +x '$MOUNT_SCRIPT'"'

echo "[+] Ubuntu Edge Node installed successfully."
echo "[+] Run 'adb shell su -c /data/local/ubuntu_mount.sh' to enter the OS."
