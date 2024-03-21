# need auto run after reboot, 
# so exec `crontab -e` to add this job: 
# 	`@reboot make -C /path/to/this/Makefile post`
target = $(subst .post.,,$(firstword $(wildcard .post.* )))

# $(call benchmark)
define benchmark
	export UB_TMPDIR=/var &&\
	export UB_RESULTDIR=$(shell realpath results) &&\
	export UB_OUTPUT_FILE_NAME=$(target).benchmark &&\
	cd byte-unixbench/UnixBench/ &&\
	./Run
endef

# $(call startup-time)
define startup-time
	systemctl is-system-running --wait &&\
	systemd-analyze > results/$(target).startup
endef

# $(call osinfo)
define osinfo
	uname -a > results/$(target).uname &&\
	cat /proc/cmdline > results/$(target).cmdline
endef


# measure performance in post stage (after reboot)
post:
	[ $(target) ] &&\
	echo "Post stage for: $(target)" &&\
	make $(target)-post || true

%-post: performance
	rm .post.$(subst -post,,$@)

performance:
	$(call osinfo) &&\
	$(call startup-time) &&\
	$(call benchmark)

# install kernel without ima (disable ima in .config)
ima-nobuildin:
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=""/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	touch .post.$@  # mark need post work
	reboot

# install kernel with ima enabled 
ima-nopolicy:
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=""/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	touch .post.$@  # mark need post work
	reboot

ima-measurement:
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ima_policy=tcb"/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	touch .post.$@
	reboot

ima-appraisal:
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ima_appraise=fix ima_policy=appraise_tcb"/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	touch .post.$@-fix
	reboot

ima-appraisal-fix-post:
	time find / -fstype ext4 -type f -uid 0 -exec dd if='{}' of=/dev/null count=0 status=none \; || true
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ima_appraise=enforce ima_policy=appraise_tcb"/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	rm .post.$(subst -post,,$@) && touch .post.ima-appraise
	reboot

ima-evm:
	# encrypted key
	keyctl add user kmk "$$(dd if=/dev/urandom bs=1 count=32 2> /dev/null)" @u
	keyctl add encrypted evm-key "new user:kmk 64" @u
	mkdir -p /etc/keys/
	keyctl pipe $$(keyctl search @u user kmk) > /etc/keys/kmk
	keyctl pipe $$(keyctl search @u encrypted evm-key) > /etc/keys/evm-key
	# update initramfs
	cp hooks-ima.sh  /etc/initramfs-tools/hooks/ima.sh
	cp local-top-ima.sh /etc/initramfs-tools/scripts/local-top/ima.sh
	update-initramfs -k `uname -r` -u
	# reboot for fix
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ima_appraise=fix evm=fix ima_policy=appraise_tcb"/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	touch .post.$@-fix
	reboot

ima-evm-fix-post:
	time find / -fstype ext4 -type f -uid 0 -exec dd if='{}' of=/dev/null count=0 status=none \; || true
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ima_appraise=enforce ima_policy=appraise_tcb"/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	rm .post.$(subst -post,,$@) && touch .post.ima-evm
	reboot

ima-evm-sign:
	# encrypted key
	keyctl add user kmk "$$(dd if=/dev/urandom bs=1 count=32 2> /dev/null)" @u
	keyctl add encrypted evm-key "new user:kmk 64" @u
	mkdir -p /etc/keys/
	keyctl pipe $$(keyctl search @u user kmk) > /etc/keys/kmk
	keyctl pipe $$(keyctl search @u encrypted evm-key) > /etc/keys/evm-key
	# generate sign rsa key
	mkdir -p /etc/keys/
	openssl genrsa -out /etc/keys/privkey_evm.pem 1024
	openssl rsa -pubout -in /etc/keys/privkey_evm.pem -out /etc/keys/pubkey_evm.pem
	# update initramfs
	cp hooks-ima-sign.sh  /etc/initramfs-tools/hooks/ima.sh
	cp local-top-ima-sign.sh /etc/initramfs-tools/scripts/local-top/ima.sh
	update-initramfs -k `uname -r` -u
	# reboot for fix
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ima_appraise=fix evm=fix ima_policy=appraise_tcb"/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	touch .post.$@-fix
	reboot

ima-evm-sign-fix-post:
	time find / -fstype ext4 -type f -uid 0 -exec $$(realpath sign_file.sh) '{}' \; || true
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ima_appraise=enforce ima_policy=appraise_tcb"/g' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg
	rm .post.$(subst -post,,$@) && touch .post.ima-evm-sign
	reboot