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
